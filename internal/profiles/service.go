// Package profiles manages the scan profiles of a project: the reusable
// recipes (which scanners run, with which configuration, against which subset
// of targets) that a scan session executes.
//
// Ownership: Agent 3.
//
// A profile is a whole recipe, so its scanner set is edited as a unit: an
// update that carries a scanner list replaces every binding in one transaction
// rather than patching individual rows. Partial edits are what produce profiles
// that half-run — a web scanner bound without the port scan that feeds it — and
// the replace-all rule makes that impossible to express.
//
// Authoring-time validation is deliberately strict, because a broken profile
// only shows up minutes later as a failed scan:
//
//   - every scanner id must exist in the scanners registry (otherwise 404);
//   - a scanner that is disabled, missing or broken is refused (409) rather
//     than silently skipped at run time;
//   - every scanner config must be a JSON object;
//   - a profile name must be unique inside its project (409).
package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

// Errors returned by the profile service.
var (
	// ErrNotFound means no profile (or no referenced row) exists.
	ErrNotFound = errors.New("scan profile not found")
	// ErrConflict means the profile name is taken in this project, or a
	// scanner cannot be bound in its current state.
	ErrConflict = errors.New("scan profile already exists")
	// ErrInvalidInput marks a malformed profile.
	ErrInvalidInput = errors.New("invalid scan profile input")
)

// Limits that keep a profile executable and the payloads bounded. The schema
// has no CHECK for these, so they are enforced here.
const (
	maxNameLength     = 200
	maxDescriptionLen = 4000
	minTimeoutSeconds = 1
	maxTimeoutSeconds = 86400 // 24h
	defaultTimeout    = 1800
	maxScanners       = 32
)

// profileCols is the canonical column list of scan_profiles.
const profileCols = `id, project_id, name, description, target_selection, excluded_targets,
	timeout_seconds, report_prefs, created_at, updated_at`

// Service provides profile operations and the /profiles HTTP surface.
type Service struct {
	db *database.DB
}

// NewService builds the profile service.
func NewService(db *database.DB) *Service { return &Service{db: db} }

// Register mounts the profile routes on the /api/v1 router.
func (s *Service) Register(r chi.Router) {
	r.Get("/projects/{id}/profiles", s.handleList)
	r.Post("/projects/{id}/profiles", s.handleCreate)
	r.Get("/profiles/{id}", s.handleGet)
	r.Put("/profiles/{id}", s.handleUpdate)
	r.Delete("/profiles/{id}", s.handleDelete)
}

// ───────────────────────────────────────────── inputs

// ScannerBinding binds one scanner, with its own configuration, to a profile.
type ScannerBinding struct {
	ScannerID uuid.UUID       `json:"scanner_id"`
	Config    json.RawMessage `json:"config"`
	SortOrder int             `json:"sort_order"`
}

// CreateInput is the service-level payload for a new profile.
type CreateInput struct {
	Name        string
	Description string
	// TargetSelection narrows the profile to a subset of the project's
	// authorized targets; empty means every authorized target.
	TargetSelection []string
	ExcludedTargets []string
	// TimeoutSeconds bounds the whole profile run; zero selects the default.
	TimeoutSeconds int
	ReportPrefs    json.RawMessage
	Scanners       []ScannerBinding
}

// UpdateInput patches a profile. A nil pointer leaves the field untouched; for
// Scanners, a nil list leaves the bindings untouched while a non-nil (even
// empty) list replaces all of them.
type UpdateInput struct {
	Name            *string
	Description     *string
	TargetSelection *[]string
	ExcludedTargets *[]string
	TimeoutSeconds  *int
	ReportPrefs     *json.RawMessage
	Scanners        *[]ScannerBinding
}

// ───────────────────────────────────────────── queries

// Get loads one profile with its scanner bindings attached.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.ScanProfile, error) {
	profile, err := scanProfile(s.db.QueryRow(ctx, `SELECT `+profileCols+` FROM scan_profiles WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	bindings, err := s.bindings(ctx, []uuid.UUID{profile.ID})
	if err != nil {
		return nil, err
	}
	profile.Scanners = bindings[profile.ID]
	return &profile, nil
}

// ListFilters narrows the project profile list.
type ListFilters struct {
	Query  string // ILIKE over name and description
	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// List returns the profiles of a project plus the total match count. Every
// returned profile carries its scanner bindings; the bindings of the whole page
// come back in one query, so the cost does not grow with the page size.
func (s *Service) List(ctx context.Context, projectID uuid.UUID, f ListFilters) ([]models.ScanProfile, int, error) {
	var projectExists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)`, projectID).Scan(&projectExists); err != nil {
		return nil, 0, err
	}
	if !projectExists {
		return nil, 0, ErrNotFound
	}

	conds := []string{"project_id = $1"}
	args := []any{projectID}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + escapeLike(q) + "%"
		args = append(args, like, like)
		conds = append(conds, fmt.Sprintf("(name ILIKE $%d ESCAPE '\\' OR description ILIKE $%d ESCAPE '\\')", len(args)-1, len(args)))
	}
	where := strings.Join(conds, " AND ")

	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM scan_profiles WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	orderBy, ok := profileSort(f.Sort, f.Desc)
	if !ok {
		return nil, 0, fmt.Errorf("%w: unknown sort %q", ErrInvalidInput, f.Sort)
	}
	args = append(args, clampInt(f.Limit, 100, 1, 1000), clampInt(f.Offset, 0, 0, 1<<31-1))
	rows, err := s.db.Query(ctx,
		`SELECT `+profileCols+` FROM scan_profiles WHERE `+where+` ORDER BY `+orderBy+
			fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	profiles := []models.ScanProfile{}
	var ids []uuid.UUID
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, 0, err
		}
		profiles = append(profiles, p)
		ids = append(ids, p.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(ids) == 0 {
		return profiles, total, nil
	}
	bindings, err := s.bindings(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range profiles {
		// A profile without bindings must serialise as an empty list, not null.
		profiles[i].Scanners = bindings[profiles[i].ID]
		if profiles[i].Scanners == nil {
			profiles[i].Scanners = []models.ProfileScanner{}
		}
	}
	return profiles, total, nil
}

// bindings loads the scanner bindings of several profiles in one query, keyed by
// profile id and ordered by sort_order then scanner name.
func (s *Service) bindings(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]models.ProfileScanner, error) {
	rows, err := s.db.Query(ctx,
		`SELECT sps.id, sps.profile_id, sps.scanner_id, sc.name, sps.config, sps.sort_order
		   FROM scan_profile_scanners sps
		   JOIN scanners sc ON sc.id = sps.scanner_id
		  WHERE sps.profile_id = ANY($1::uuid[])
		  ORDER BY sps.sort_order, sc.name, sps.id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID][]models.ProfileScanner{}
	for rows.Next() {
		var b models.ProfileScanner
		if err := rows.Scan(&b.ID, &b.ProfileID, &b.ScannerID, &b.Scanner, &b.Config, &b.SortOrder); err != nil {
			return nil, err
		}
		if len(b.Config) == 0 {
			b.Config = json.RawMessage(`{}`)
		}
		out[b.ProfileID] = append(out[b.ProfileID], b)
	}
	return out, rows.Err()
}

// ───────────────────────────────────────────── mutations

// Create inserts a profile and its scanner bindings in one transaction, so a
// profile can never exist without the scanners it was authored with.
func (s *Service) Create(ctx context.Context, projectID uuid.UUID, in CreateInput) (*models.ScanProfile, error) {
	name := strings.TrimSpace(in.Name)
	if err := validateProfileFields(name, in.Description, in.TimeoutSeconds); err != nil {
		return nil, err
	}
	timeout := in.TimeoutSeconds
	if timeout == 0 {
		timeout = defaultTimeout
	}
	prefs, err := normalizeJSON(in.ReportPrefs, "{}")
	if err != nil {
		return nil, fmt.Errorf("%w: report_prefs: %v", ErrInvalidInput, err)
	}
	bindings, err := s.resolveBindings(ctx, in.Scanners)
	if err != nil {
		return nil, err
	}
	targets := normalizeList(in.TargetSelection)
	excluded := normalizeList(in.ExcludedTargets)

	var id uuid.UUID
	err = s.db.InTx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)`, projectID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		if err := assertNameFree(ctx, tx, projectID, name, uuid.Nil); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO scan_profiles (project_id, name, description, target_selection, excluded_targets,
			                            timeout_seconds, report_prefs, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,now(),now()) RETURNING id`,
			projectID, name, in.Description, targets, excluded, timeout, prefs).Scan(&id); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a profile named %q already exists in this project", ErrConflict, name)
			}
			return err
		}
		return insertBindings(ctx, tx, id, bindings)
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Update patches a profile and, when a scanner list is supplied, replaces every
// binding in the same transaction.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*models.ScanProfile, error) {
	// Validate everything before touching the database: a request that names
	// an unknown scanner must not rename the profile on its way out.
	var bindings []bindingRow
	if in.Scanners != nil {
		resolved, err := s.resolveBindings(ctx, *in.Scanners)
		if err != nil {
			return nil, err
		}
		bindings = resolved
	}
	var (
		name     *string
		prefs    *string
		timeout  = in.TimeoutSeconds
		targets  *[]string
		excluded *[]string
	)
	if in.Name != nil {
		trimmed := strings.TrimSpace(*in.Name)
		if err := validateName(trimmed); err != nil {
			return nil, err
		}
		name = &trimmed
	}
	if in.Description != nil {
		if len(*in.Description) > maxDescriptionLen {
			return nil, fmt.Errorf("%w: description is longer than %d characters", ErrInvalidInput, maxDescriptionLen)
		}
	}
	if timeout != nil && (*timeout < minTimeoutSeconds || *timeout > maxTimeoutSeconds) {
		return nil, fmt.Errorf("%w: timeout_seconds must be between %d and %d", ErrInvalidInput, minTimeoutSeconds, maxTimeoutSeconds)
	}
	if in.ReportPrefs != nil {
		normalized, err := normalizeJSON(*in.ReportPrefs, "{}")
		if err != nil {
			return nil, fmt.Errorf("%w: report_prefs: %v", ErrInvalidInput, err)
		}
		prefs = &normalized
	}
	if in.TargetSelection != nil {
		v := normalizeList(*in.TargetSelection)
		targets = &v
	}
	if in.ExcludedTargets != nil {
		v := normalizeList(*in.ExcludedTargets)
		excluded = &v
	}

	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		var (
			current   uuid.UUID
			projectID uuid.UUID
		)
		if err := tx.QueryRow(ctx,
			`SELECT id, project_id FROM scan_profiles WHERE id = $1 FOR UPDATE`, id).
			Scan(&current, &projectID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if name != nil {
			if err := assertNameFree(ctx, tx, projectID, *name, id); err != nil {
				return err
			}
		}

		// One statement per patch: the column list is built from the fields the
		// request actually carried, so untouched columns are never rewritten.
		var sets []string
		var args []any
		add := func(column string, value any) {
			args = append(args, value)
			sets = append(sets, fmt.Sprintf("%s = $%d", column, len(args)))
		}
		if name != nil {
			add("name", *name)
		}
		if in.Description != nil {
			add("description", *in.Description)
		}
		if timeout != nil {
			add("timeout_seconds", *timeout)
		}
		if prefs != nil {
			args = append(args, *prefs)
			sets = append(sets, fmt.Sprintf("report_prefs = $%d::jsonb", len(args)))
		}
		if targets != nil {
			add("target_selection", *targets)
		}
		if excluded != nil {
			add("excluded_targets", *excluded)
		}
		if len(sets) > 0 {
			sets = append(sets, "updated_at = now()")
			args = append(args, id)
			if _, err := tx.Exec(ctx,
				`UPDATE scan_profiles SET `+strings.Join(sets, ", ")+fmt.Sprintf(" WHERE id = $%d", len(args)),
				args...); err != nil {
				if isUniqueViolation(err) && name != nil {
					return fmt.Errorf("%w: a profile named %q already exists in this project", ErrConflict, *name)
				}
				return err
			}
		}

		if in.Scanners != nil {
			// Replace-all: the profile's scanner set is the list that was sent,
			// nothing else. The delete and the inserts share this transaction,
			// so readers never observe a profile without scanners.
			if _, err := tx.Exec(ctx, `DELETE FROM scan_profile_scanners WHERE profile_id = $1`, id); err != nil {
				return err
			}
			if err := insertBindings(ctx, tx, id, bindings); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE scan_profiles SET updated_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Delete removes a profile; its bindings cascade. Past scan sessions keep their
// own copy of the target and scanner lists (scan_sessions.profile_id is
// ON DELETE SET NULL), so deleting a recipe never rewrites assessment history.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM scan_profiles WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ───────────────────────────────────────────── validation

// bindingRow is a validated binding ready for insertion.
type bindingRow struct {
	scannerID uuid.UUID
	config    string
	sortOrder int
}

// resolveBindings validates a scanner list against the registry: the ids must
// exist, a scanner may appear only once, a scanner that is switched off or
// broken cannot be bound, and every config must be a JSON object.
func (s *Service) resolveBindings(ctx context.Context, in []ScannerBinding) ([]bindingRow, error) {
	if len(in) > maxScanners {
		return nil, fmt.Errorf("%w: a profile binds at most %d scanners", ErrInvalidInput, maxScanners)
	}
	if len(in) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, 0, len(in))
	seen := map[uuid.UUID]bool{}
	for _, b := range in {
		if b.ScannerID == uuid.Nil {
			return nil, fmt.Errorf("%w: scanner_id is required", ErrInvalidInput)
		}
		if seen[b.ScannerID] {
			return nil, fmt.Errorf("%w: scanner %s is bound more than once", ErrInvalidInput, b.ScannerID)
		}
		seen[b.ScannerID] = true
		ids = append(ids, b.ScannerID)
	}

	rows, err := s.db.Query(ctx,
		`SELECT id, name, enabled, status FROM scanners WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type registryEntry struct {
		name    string
		enabled bool
		status  string
	}
	found := map[uuid.UUID]registryEntry{}
	for rows.Next() {
		var (
			id    uuid.UUID
			entry registryEntry
		)
		if err := rows.Scan(&id, &entry.name, &entry.enabled, &entry.status); err != nil {
			return nil, err
		}
		found[id] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]bindingRow, 0, len(in))
	for _, b := range in {
		entry, ok := found[b.ScannerID]
		if !ok {
			return nil, fmt.Errorf("%w: scanner %s is not installed", ErrNotFound, b.ScannerID)
		}
		if !entry.enabled || entry.status == "disabled" || entry.status == "missing" || entry.status == "error" {
			return nil, fmt.Errorf("%w: scanner %s cannot be bound while it is %s",
				ErrConflict, entry.name, scannerState(entry.enabled, entry.status))
		}
		config, err := normalizeJSON(b.Config, "{}")
		if err != nil {
			return nil, fmt.Errorf("%w: config for scanner %s: %v", ErrInvalidInput, entry.name, err)
		}
		if !isObject(config) {
			return nil, fmt.Errorf("%w: config for scanner %s must be a JSON object", ErrInvalidInput, entry.name)
		}
		if b.SortOrder < 0 {
			return nil, fmt.Errorf("%w: sort_order must not be negative", ErrInvalidInput)
		}
		out = append(out, bindingRow{scannerID: b.ScannerID, config: config, sortOrder: b.SortOrder})
	}
	return out, nil
}

func insertBindings(ctx context.Context, tx pgx.Tx, profileID uuid.UUID, bindings []bindingRow) error {
	for _, b := range bindings {
		if _, err := tx.Exec(ctx,
			`INSERT INTO scan_profile_scanners (profile_id, scanner_id, config, sort_order)
			 VALUES ($1, $2, $3::jsonb, $4)`,
			profileID, b.scannerID, b.config, b.sortOrder); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: scanner %s is bound more than once", ErrInvalidInput, b.scannerID)
			}
			if isForeignKeyViolation(err) {
				return fmt.Errorf("%w: scanner %s is not installed", ErrNotFound, b.scannerID)
			}
			return err
		}
	}
	return nil
}

// assertNameFree enforces the (project_id, name) uniqueness the schema declares.
// The comparison is case-insensitive on purpose: "Web Scan" and "web scan" as
// two different profiles would be a trap, and the unique index cannot express
// that. A concurrent pair of inserts that differ only in case can still slip
// past this check, which is why the unique index remains the authority.
func assertNameFree(ctx context.Context, tx pgx.Tx, projectID uuid.UUID, name string, exclude uuid.UUID) error {
	var taken bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM scan_profiles
		  WHERE project_id = $1 AND lower(name) = lower($2) AND id <> $3)`,
		projectID, name, exclude).Scan(&taken); err != nil {
		return err
	}
	if taken {
		return fmt.Errorf("%w: a profile named %q already exists in this project", ErrConflict, name)
	}
	return nil
}

func validateProfileFields(name, description string, timeout int) error {
	if err := validateName(name); err != nil {
		return err
	}
	if len(description) > maxDescriptionLen {
		return fmt.Errorf("%w: description is longer than %d characters", ErrInvalidInput, maxDescriptionLen)
	}
	if timeout != 0 && (timeout < minTimeoutSeconds || timeout > maxTimeoutSeconds) {
		return fmt.Errorf("%w: timeout_seconds must be between %d and %d", ErrInvalidInput, minTimeoutSeconds, maxTimeoutSeconds)
	}
	return nil
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if len(name) > maxNameLength {
		return fmt.Errorf("%w: name is longer than %d characters", ErrInvalidInput, maxNameLength)
	}
	if strings.ContainsAny(name, "\r\n\t\x00") {
		return fmt.Errorf("%w: name must be a single line", ErrInvalidInput)
	}
	return nil
}

func scannerState(enabled bool, status string) string {
	if !enabled {
		return "disabled"
	}
	return status
}

// normalizeList trims entries, drops blanks and removes exact duplicates while
// keeping the order the caller used.
func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// normalizeJSON validates a jsonb payload and applies a default when it is
// absent.
func normalizeJSON(raw json.RawMessage, def string) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return def, nil
	}
	if !json.Valid([]byte(trimmed)) {
		return "", errors.New("is not valid JSON")
	}
	return trimmed, nil
}

func isObject(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23503"
}

// ───────────────────────────────────────────── HTTP

type scannerBindingRequest struct {
	ScannerID uuid.UUID       `json:"scanner_id"`
	Config    json.RawMessage `json:"config"`
	SortOrder int             `json:"sort_order"`
}

type createProfileRequest struct {
	Name            string                  `json:"name"`
	Description     string                  `json:"description"`
	TargetSelection []string                `json:"target_selection"`
	ExcludedTargets []string                `json:"excluded_targets"`
	TimeoutSeconds  int                     `json:"timeout_seconds"`
	ReportPrefs     json.RawMessage         `json:"report_prefs"`
	Scanners        []scannerBindingRequest `json:"scanners"`
}

type updateProfileRequest struct {
	Name            *string                  `json:"name"`
	Description     *string                  `json:"description"`
	TargetSelection *[]string                `json:"target_selection"`
	ExcludedTargets *[]string                `json:"excluded_targets"`
	TimeoutSeconds  *int                     `json:"timeout_seconds"`
	ReportPrefs     *json.RawMessage         `json:"report_prefs"`
	Scanners        *[]scannerBindingRequest `json:"scanners"`
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q := r.URL.Query()
	filters := ListFilters{
		Query:  q.Get("q"),
		Sort:   q.Get("sort"),
		Desc:   strings.EqualFold(q.Get("order"), "desc"),
		Limit:  intQuery(r, "limit", 100),
		Offset: intQuery(r, "offset", 0),
	}
	items, total, err := s.List(r.Context(), projectID, filters)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteList(w, items, total)
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body createProfileRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	profile, err := s.Create(r.Context(), projectID, CreateInput{
		Name: body.Name, Description: body.Description,
		TargetSelection: body.TargetSelection, ExcludedTargets: body.ExcludedTargets,
		TimeoutSeconds: body.TimeoutSeconds, ReportPrefs: body.ReportPrefs,
		Scanners: convertBindings(body.Scanners),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusCreated, profile)
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	profile, err := s.Get(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, profile)
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body updateProfileRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	in := UpdateInput{
		Name: body.Name, Description: body.Description,
		TargetSelection: body.TargetSelection, ExcludedTargets: body.ExcludedTargets,
		TimeoutSeconds: body.TimeoutSeconds, ReportPrefs: body.ReportPrefs,
	}
	if body.Scanners != nil {
		converted := convertBindings(*body.Scanners)
		in.Scanners = &converted
	}
	profile, err := s.Update(r.Context(), id, in)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, profile)
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.Delete(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func convertBindings(in []scannerBindingRequest) []ScannerBinding {
	if in == nil {
		return nil
	}
	out := make([]ScannerBinding, 0, len(in))
	for _, b := range in {
		out = append(out, ScannerBinding{ScannerID: b.ScannerID, Config: b.Config, SortOrder: b.SortOrder})
	}
	return out
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		api.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		api.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrInvalidInput):
		api.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		api.WriteError(w, http.StatusInternalServerError, "scan profile operation failed")
	}
}

func scanProfile(row pgx.Row) (models.ScanProfile, error) {
	var p models.ScanProfile
	err := row.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.TargetSelection,
		&p.ExcludedTargets, &p.TimeoutSeconds, &p.ReportPrefs, &p.CreatedAt, &p.UpdatedAt)
	if p.TargetSelection == nil {
		p.TargetSelection = []string{}
	}
	if p.ExcludedTargets == nil {
		p.ExcludedTargets = []string{}
	}
	if len(p.ReportPrefs) == 0 {
		p.ReportPrefs = json.RawMessage(`{}`)
	}
	return p, err
}

func profileSort(field string, desc bool) (string, bool) {
	if field == "" {
		field = "name"
	}
	col, ok := map[string]string{
		"name":            "lower(name)",
		"created_at":      "created_at",
		"updated_at":      "updated_at",
		"timeout_seconds": "timeout_seconds",
	}[field]
	if !ok {
		return "", false
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return col + " " + dir + ", id ASC", true
}

func pathUUID(w http.ResponseWriter, r *http.Request, key string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, key))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid "+key)
		return uuid.Nil, false
	}
	return id, true
}

func intQuery(r *http.Request, key string, def int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func clampInt(v, def, min, max int) int {
	if v < min {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}
