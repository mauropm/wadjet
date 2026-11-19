package projects

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/models"
)

// CopyOptions selects which configuration facets a clone inherits. Each flag
// is honoured independently; there is no implicit coupling between them.
//
// The clone never receives historical data: scan_sessions, scan_session_targets,
// scanner_executions, findings, finding_observations, asset_observations and
// finding_status_history rows are never copied, regardless of these flags.
type CopyOptions struct {
	// Settings copies projects.settings verbatim.
	Settings bool
	// Targets copies project_targets (included and excluded entries).
	Targets bool
	// ScannerConfigs copies project scanner_configurations.
	ScannerConfigs bool
	// Profiles copies scan_profiles and their scan_profile_scanners bindings.
	Profiles bool
	// Tags copies the project tag list.
	Tags bool
	// ReportPrefs copies report preferences: the project "report_prefs" key
	// inside settings, and scan_profiles.report_prefs for copied profiles.
	ReportPrefs bool
}

// DefaultCopyOptions is what Clone uses when the request omits "copy": every
// configuration facet is duplicated.
func DefaultCopyOptions() CopyOptions {
	return CopyOptions{Settings: true, Targets: true, ScannerConfigs: true, Profiles: true, Tags: true, ReportPrefs: true}
}

// CloneInput describes the new project. Empty Name defaults to
// "<original> (Clone)"; a nil Description inherits the original description.
type CloneInput struct {
	Name        string
	Description *string
	Copy        CopyOptions
}

// Clone creates a new independent project from an existing one.
//
// All cloned rows are inserted without their primary keys so PostgreSQL
// assigns fresh IDs via gen_random_uuid(); nothing references the original
// rows, which makes the clone fully editable and independent: mutating the
// clone can never touch the original.
//
// The whole clone is one transaction: a failure in any facet rolls back the
// new project as well.
func (s *Service) Clone(ctx context.Context, sourceID uuid.UUID, in CloneInput, actor *uuid.UUID) (*models.Project, error) {
	var created models.Project
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		src, err := scanProject(tx.QueryRow(ctx,
			`SELECT `+projectCols+` FROM projects WHERE id = $1`, sourceID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = src.Name + " (Clone)"
		}
		if len([]rune(name)) > 200 {
			return ErrInvalidInput
		}
		description := src.Description
		if in.Description != nil {
			description = *in.Description
		}
		tags := []string{}
		if in.Copy.Tags {
			tags = src.Tags
		}
		settings := composeSettings(src.Settings, in.Copy)

		if err := tx.QueryRow(ctx,
			`INSERT INTO projects (name, description, status, tags, settings, created_by, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, now())
			 RETURNING `+projectCols,
			name, description, models.ProjectStatusActive, tags, settings, actor).
			Scan(&created.ID, &created.Name, &created.Description, &created.Status, &created.Tags,
				&created.Settings, &created.CreatedBy, &created.CreatedAt, &created.UpdatedAt, &created.LastActivity); err != nil {
			return fmt.Errorf("insert cloned project: %w", err)
		}
		if created.Tags == nil {
			created.Tags = []string{}
		}

		if in.Copy.Targets {
			if _, err := tx.Exec(ctx,
				`INSERT INTO project_targets (project_id, target, target_type, excluded, note)
				 SELECT $2, target, target_type, excluded, note
				   FROM project_targets WHERE project_id = $1
				   ORDER BY created_at, target`, sourceID, created.ID); err != nil {
				return fmt.Errorf("clone targets: %w", err)
			}
		}

		if in.Copy.ScannerConfigs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO scanner_configurations (project_id, scanner_id, config, updated_at)
				 SELECT $2, scanner_id, config, now()
				   FROM scanner_configurations WHERE project_id = $1`, sourceID, created.ID); err != nil {
				return fmt.Errorf("clone scanner configs: %w", err)
			}
		}

		if in.Copy.Profiles {
			if err := cloneProfiles(ctx, tx, sourceID, created.ID, in.Copy.ReportPrefs); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// cloneProfiles copies scan_profiles plus their scanner bindings. Profiles are
// matched between original and clone by name, which is unique per project.
func cloneProfiles(ctx context.Context, tx pgx.Tx, srcProject, dstProject uuid.UUID, copyReportPrefs bool) error {
	rows, err := tx.Query(ctx,
		`SELECT name, description, target_selection, excluded_targets, timeout_seconds, report_prefs
		   FROM scan_profiles WHERE project_id = $1 ORDER BY created_at, name`, srcProject)
	if err != nil {
		return fmt.Errorf("read profiles: %w", err)
	}
	type prof struct {
		name        string
		description string
		targets     []string
		excluded    []string
		timeout     int
		reportPrefs json.RawMessage
	}
	var profs []prof
	for rows.Next() {
		var p prof
		if err := rows.Scan(&p.name, &p.description, &p.targets, &p.excluded, &p.timeout, &p.reportPrefs); err != nil {
			rows.Close()
			return fmt.Errorf("scan profile: %w", err)
		}
		profs = append(profs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, p := range profs {
		prefs := json.RawMessage(`{}`)
		if copyReportPrefs && len(p.reportPrefs) > 0 {
			prefs = p.reportPrefs
		}
		var newID uuid.UUID
		if err := tx.QueryRow(ctx,
			`INSERT INTO scan_profiles (project_id, name, description, target_selection, excluded_targets,
				                        timeout_seconds, report_prefs, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now()) RETURNING id`,
			dstProject, p.name, p.description, p.targets, p.excluded, p.timeout, prefs).Scan(&newID); err != nil {
			return fmt.Errorf("clone profile %q: %w", p.name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO scan_profile_scanners (profile_id, scanner_id, config, sort_order)
			 SELECT $2, sps.scanner_id, sps.config, sps.sort_order
			   FROM scan_profiles op
			   JOIN scan_profile_scanners sps ON sps.profile_id = op.id
			  WHERE op.project_id = $1 AND op.name = $3`, srcProject, newID, p.name); err != nil {
			return fmt.Errorf("clone profile scanners: %w", err)
		}
	}
	return nil
}

// composeSettings builds the clone's settings JSON from the selected facets.
func composeSettings(orig json.RawMessage, opts CopyOptions) json.RawMessage {
	base := map[string]json.RawMessage{}
	var src map[string]json.RawMessage
	if json.Unmarshal(orig, &src) == nil {
		if opts.Settings {
			for k, v := range src {
				base[k] = v
			}
		}
		if opts.ReportPrefs {
			if rp, ok := src["report_prefs"]; ok {
				base["report_prefs"] = rp
			}
		}
	}
	out, err := json.Marshal(base)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}

// ───────────────────────────────────────────── HTTP

type cloneCopyRequest struct {
	Settings       *bool `json:"settings"`
	Targets        *bool `json:"targets"`
	ScannerConfigs *bool `json:"scanner_configs"`
	Profiles       *bool `json:"profiles"`
	Tags           *bool `json:"tags"`
	ReportPrefs    *bool `json:"report_prefs"`
}

type cloneRequest struct {
	Name        string            `json:"name"`
	Description *string           `json:"description"`
	Copy        *cloneCopyRequest `json:"copy"`
}

func (c *cloneCopyRequest) options() CopyOptions {
	opts := DefaultCopyOptions()
	if c == nil {
		return opts
	}
	pick := func(src *bool, dst *bool) {
		if src != nil {
			*dst = *src
		}
	}
	pick(c.Settings, &opts.Settings)
	pick(c.Targets, &opts.Targets)
	pick(c.ScannerConfigs, &opts.ScannerConfigs)
	pick(c.Profiles, &opts.Profiles)
	pick(c.Tags, &opts.Tags)
	pick(c.ReportPrefs, &opts.ReportPrefs)
	return opts
}

func (s *Service) handleClone(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	var body cloneRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	user := api.UserFromContext(r.Context())
	var actor *uuid.UUID
	if user != nil {
		actor = &user.ID
	}
	opts := body.Copy.options()
	clone, err := s.Clone(r.Context(), id, CloneInput{
		Name:        body.Name,
		Description: body.Description,
		Copy:        opts,
	}, actor)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	s.log(r, user, "project.clone", clone, map[string]any{"source_id": id.String(), "copy": opts})
	api.WriteJSON(w, http.StatusCreated, clone)
}
