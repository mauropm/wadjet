// Package targets manages the authorized scan scope of a project and provides
// the security gate the scan orchestrator consults before every execution.
//
// Ownership: Agent 3.
//
// # Authorization model
//
// A project holds included and excluded entries. A target is authorized when
// at least one included entry covers it and no excluded entry does. Exclusions
// always win and a project without included entries authorizes nothing, so the
// gate fails closed. See Check and matchesEntry in authorize.go for the exact
// matching rules.
package targets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

// Sentinel errors. Callers distinguish a malformed target from an out-of-scope
// one and from an explicitly excluded one.
var (
	// ErrInvalidTarget means the string is not a valid IP, CIDR, hostname,
	// domain or http(s) URL.
	ErrInvalidTarget = errors.New("invalid target")
	// ErrNotAuthorized means no included entry of the project covers the target.
	ErrNotAuthorized = errors.New("target is not authorized")
	// ErrExcluded means an excluded entry matches, which overrides any include.
	ErrExcluded = errors.New("target is excluded")
	// ErrNotFound means the project or target row does not exist.
	ErrNotFound = errors.New("target not found")
	// ErrConflict means an equivalent entry already exists.
	ErrConflict = errors.New("target already exists")
	// ErrInvalidInput marks malformed request payloads.
	ErrInvalidInput = errors.New("invalid target input")
)

// validTargetTypes mirrors the project_targets.target_type CHECK constraint.
var validTargetTypes = map[string]bool{
	KindAuto: true, KindIP: true, KindIPv6: true, KindCIDR: true,
	KindHostname: true, KindDomain: true, KindURL: true,
}

// Service provides project target operations and the HTTP surface.
type Service struct {
	db *database.DB
}

// NewService builds the target service.
func NewService(db *database.DB) *Service { return &Service{db: db} }

// Register mounts the target routes on the /api/v1 router.
func (s *Service) Register(r chi.Router) {
	r.Get("/projects/{id}/targets", s.handleList)
	r.Post("/projects/{id}/targets", s.handleCreate)
	r.Put("/targets/{id}", s.handleUpdate)
	r.Delete("/targets/{id}", s.handleDelete)
}

// ───────────────────────────────────────────── the security gate

// Authorize is the gate the scan orchestrator calls for every target before a
// scanner touches the network.
//
// It returns:
//
//	ErrInvalidTarget   the string cannot be parsed as a target
//	ErrExcluded        an excluded entry matches (overrides includes)
//	ErrNotAuthorized   no included entry matches, including the case where the
//	                   project has no targets at all
//	nil                the target is inside the project scope
//
// The check performs no DNS lookups: an IP target must be authorized by an IP
// or CIDR entry and a hostname by a hostname or domain entry.
func (s *Service) Authorize(ctx context.Context, projectID uuid.UUID, target string) error {
	parsed, err := ParseTarget(target)
	if err != nil {
		return err
	}
	entries, err := s.entries(ctx, projectID)
	if err != nil {
		return err
	}
	return Check(parsed, entries)
}

// AuthorizeTargets checks every target and returns the first failure together
// with the index it happened at, which is what the orchestrator records on
// scan_session_targets as status "denied".
func (s *Service) AuthorizeTargets(ctx context.Context, projectID uuid.UUID, targets []string) (int, error) {
	entries, err := s.entries(ctx, projectID)
	if err != nil {
		return 0, err
	}
	for i, raw := range targets {
		parsed, err := ParseTarget(raw)
		if err != nil {
			return i, err
		}
		if err := Check(parsed, entries); err != nil {
			return i, err
		}
	}
	return 0, nil
}

// entries loads the project's configured targets.
func (s *Service) entries(ctx context.Context, projectID uuid.UUID) ([]Entry, error) {
	rows, err := s.db.Query(ctx,
		`SELECT target, target_type, excluded FROM project_targets WHERE project_id = $1 ORDER BY created_at, target`,
		projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Target, &e.TargetType, &e.Excluded); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ───────────────────────────────────────────── CRUD

// Create inserts one target entry. targetType may be empty (stored as "auto"),
// in which case the shape detected by ParseTarget is stored.
func (s *Service) Create(ctx context.Context, projectID uuid.UUID, target, targetType, note string, excluded bool) (*models.ProjectTarget, error) {
	target = strings.TrimSpace(target)
	targetType, err := validateEntry(targetType, target)
	if err != nil {
		return nil, err
	}
	// The table's unique key is (project_id, target, excluded); hostnames are
	// matched case-insensitively, so reject "WWW.example.com" next to
	// "www.example.com" instead of silently keeping both.
	dup, err := s.findEquivalent(ctx, projectID, target, excluded, uuid.Nil)
	if err != nil {
		return nil, err
	}
	if dup {
		return nil, ErrConflict
	}
	var t models.ProjectTarget
	err = s.db.QueryRow(ctx,
		`INSERT INTO project_targets (project_id, target, target_type, excluded, note)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, project_id, target, target_type, excluded, note, created_at`,
		projectID, target, targetType, excluded, note).
		Scan(&t.ID, &t.ProjectID, &t.Target, &t.TargetType, &t.Excluded, &t.Note, &t.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		if isMissingRelation(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// Update modifies an entry. nil fields are left unchanged.
func (s *Service) Update(ctx context.Context, id uuid.UUID, target, targetType, note *string, excluded *bool) (*models.ProjectTarget, error) {
	var current models.ProjectTarget
	err := s.db.QueryRow(ctx,
		`SELECT id, project_id, target, target_type, excluded, note, created_at FROM project_targets WHERE id = $1`, id).
		Scan(&current.ID, &current.ProjectID, &current.Target, &current.TargetType, &current.Excluded, &current.Note, &current.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	newTarget, newType, newNote := current.Target, current.TargetType, current.Note
	newExcluded := current.Excluded
	if target != nil {
		newTarget = strings.TrimSpace(*target)
	}
	if targetType != nil {
		newType = *targetType
	}
	if note != nil {
		newNote = *note
	}
	if excluded != nil {
		newExcluded = *excluded
	}
	newType, err = validateEntry(newType, newTarget)
	if err != nil {
		return nil, err
	}
	dup, err := s.findEquivalent(ctx, current.ProjectID, newTarget, newExcluded, id)
	if err != nil {
		return nil, err
	}
	if dup {
		return nil, ErrConflict
	}
	var out models.ProjectTarget
	err = s.db.QueryRow(ctx,
		`UPDATE project_targets SET target = $2, target_type = $3, excluded = $4, note = $5
		 WHERE id = $1
		 RETURNING id, project_id, target, target_type, excluded, note, created_at`,
		id, newTarget, newType, newExcluded, newNote).
		Scan(&out.ID, &out.ProjectID, &out.Target, &out.TargetType, &out.Excluded, &out.Note, &out.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &out, nil
}

// Delete removes an entry owned by any project; the row is identified by id.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM project_targets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns the project's entries, newest first within each group.
func (s *Service) List(ctx context.Context, projectID uuid.UUID) ([]models.ProjectTarget, int, error) {
	if _, err := s.projectExists(ctx, projectID); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, project_id, target, target_type, excluded, note, created_at
		 FROM project_targets WHERE project_id = $1 ORDER BY excluded, target, created_at`, projectID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []models.ProjectTarget{}
	for rows.Next() {
		var t models.ProjectTarget
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.Target, &t.TargetType, &t.Excluded, &t.Note, &t.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, len(out), nil
}

func (s *Service) projectExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var ok bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)`, id).Scan(&ok); err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotFound
	}
	return true, nil
}

// findEquivalent reports whether an entry with the same meaning already
// exists: same project, same excluded flag and the same target compared
// case-insensitively (hostnames are matched case-insensitively anyway).
func (s *Service) findEquivalent(ctx context.Context, projectID uuid.UUID, target string, excluded bool, excludeID uuid.UUID) (bool, error) {
	var found bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM project_targets
		        WHERE project_id = $1 AND excluded = $2 AND lower(target) = lower($3)
		          AND ($4::uuid IS NULL OR id <> $4))`,
		projectID, excluded, target, nullableUUID(excludeID)).Scan(&found)
	return found, err
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// validateEntry checks the declared type against the parsed shape so an entry
// can never be stored in a state the gate would consider inert.
func validateEntry(targetType, target string) (string, error) {
	if targetType == "" {
		targetType = KindAuto
	}
	if !validTargetTypes[targetType] {
		return "", fmt.Errorf("%w: unknown target_type %q", ErrInvalidInput, targetType)
	}
	parsed, err := ParseTarget(target)
	if err != nil {
		return "", err
	}
	switch targetType {
	case KindAuto:
		return KindAuto, nil
	case KindIP, KindIPv6, KindCIDR:
		if parsed.Kind != targetType {
			return "", fmt.Errorf("%w: %q is not a %s", ErrInvalidInput, target, targetType)
		}
	case KindHostname, KindDomain, KindURL:
		if parsed.Host == "" {
			return "", fmt.Errorf("%w: %q is not a %s", ErrInvalidInput, target, targetType)
		}
	}
	return targetType, nil
}

// ───────────────────────────────────────────── HTTP

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	items, total, err := s.List(r.Context(), projectID)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteList(w, items, total)
}

type createTargetRequest struct {
	Target     string `json:"target"`
	TargetType string `json:"target_type"`
	Note       string `json:"note"`
	Excluded   bool   `json:"excluded"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body createTargetRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	t, err := s.Create(r.Context(), projectID, body.Target, body.TargetType, body.Note, body.Excluded)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusCreated, t)
}

type updateTargetRequest struct {
	Target     *string `json:"target"`
	TargetType *string `json:"target_type"`
	Note       *string `json:"note"`
	Excluded   *bool   `json:"excluded"`
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body updateTargetRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	t, err := s.Update(r.Context(), id, body.Target, body.TargetType, body.Note, body.Excluded)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, t)
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

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		api.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		api.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrInvalidTarget), errors.Is(err, ErrInvalidInput):
		api.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		api.WriteError(w, http.StatusInternalServerError, "target operation failed")
	}
}

func pathUUID(w http.ResponseWriter, r *http.Request, key string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, key))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid "+key)
		return uuid.Nil, false
	}
	return id, true
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key value")
}

func isMissingRelation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "violates foreign key")
}
