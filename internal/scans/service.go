// Package scans exposes the scan-session REST API: creation of ad-hoc or
// profile-driven scan sessions, listing, detail, async start, cancellation,
// and a per-session Server-Sent Events stream.
package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

// Registry is the scanner-registry surface consumed by this service.
type Registry interface {
	List(ctx context.Context) ([]models.ScannerRecord, error)
	GetRecord(ctx context.Context, idOrName string) (models.ScannerRecord, error)
	Enable(ctx context.Context, name string) error
	Disable(ctx context.Context, name string) error
	CheckAvailability(ctx context.Context, name string) (models.ScannerRecord, error)
	Enabled(name string) bool
	// Manifest exposes the scanner's manifest so scan creation can
	// validate configuration up front (DEF-2) instead of failing the
	// execution asynchronously.
	Manifest(name string) (*manifest.Manifest, bool)
}

// Orchestrator is the execution surface consumed by this service.
type Orchestrator interface {
	StartSession(ctx context.Context, sessionID uuid.UUID) error
	Cancel(sessionID uuid.UUID) bool
	// ValidateTargets enforces the project scope allowlist at creation time.
	ValidateTargets(ctx context.Context, projectID uuid.UUID, targets []string) error
}

// Service serves the scanners & scans REST surface. It is mounted at
// /api/v1 with auth already applied.
type Service struct {
	db   *database.DB
	reg  Registry
	orch Orchestrator
	bus  *events.Bus
}

// NewService creates the scans service.
func NewService(db *database.DB, reg Registry, orch Orchestrator, bus *events.Bus) *Service {
	return &Service{db: db, reg: reg, orch: orch, bus: bus}
}

// Register mounts the scanners & scans routes on r (mounted at /api/v1).
func (s *Service) Register(r chi.Router) {
	r.Get("/scanners", s.listScanners)
	r.Get("/scanners/{id}", s.getScanner)
	r.With(api.RequireAdmin).Put("/scanners/{id}/enabled", s.setScannerEnabled)
	r.Post("/scanners/{id}/check", s.checkScanner)

	r.Post("/projects/{id}/scans", s.createScan)
	r.Get("/projects/{id}/scans", s.listScans)
	r.Get("/scans/{id}", s.getScan)
	r.Post("/scans/{id}/start", s.startScan)
	r.Post("/scans/{id}/cancel", s.cancelScan)
	r.Get("/scans/{id}/events", s.streamEvents)
}

// ── session persistence helpers ─────────────────────────────────────────

const sessionColumns = `id, project_id, profile_id, name, status, targets, scanner_names,
	assets_processed, findings_created, findings_updated, error,
	started_at, finished_at, duration_ms, created_by, created_at, updated_at`

func scanSession(row pgx.Row) (models.ScanSession, error) {
	var sm models.ScanSession
	err := row.Scan(&sm.ID, &sm.ProjectID, &sm.ProfileID, &sm.Name, &sm.Status,
		&sm.Targets, &sm.ScannerNames, &sm.AssetsProcessed, &sm.FindingsCreated,
		&sm.FindingsUpdated, &sm.Error, &sm.StartedAt, &sm.FinishedAt, &sm.DurationMS,
		&sm.CreatedBy, &sm.CreatedAt, &sm.UpdatedAt)
	return sm, err
}

const executionColumns = `id, session_id, scanner_name, status, config, targets,
	raw_output_path, raw_output_bytes, assets_observed, findings_found,
	error, log, started_at, finished_at, created_at`

func scanExecution(row pgx.Row) (models.ScannerExecution, error) {
	var ex models.ScannerExecution
	err := row.Scan(&ex.ID, &ex.SessionID, &ex.ScannerName, &ex.Status, &ex.Config,
		&ex.Targets, &ex.RawOutputPath, &ex.RawOutputBytes, &ex.AssetsObserved,
		&ex.FindingsFound, &ex.Error, &ex.Log, &ex.StartedAt, &ex.FinishedAt, &ex.CreatedAt)
	return ex, err
}

func (s *Service) getSession(ctx context.Context, id uuid.UUID) (models.ScanSession, []models.ScannerExecution, []sessionTarget, error) {
	sm, err := scanSession(s.db.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM scan_sessions WHERE id = $1`, id))
	if err != nil {
		return sm, nil, nil, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+executionColumns+` FROM scanner_executions WHERE session_id = $1 ORDER BY created_at, scanner_name`, id)
	if err != nil {
		return sm, nil, nil, fmt.Errorf("scans: load executions: %w", err)
	}
	defer rows.Close()
	var execs []models.ScannerExecution
	for rows.Next() {
		ex, err := scanExecution(rows)
		if err != nil {
			return sm, nil, nil, err
		}
		execs = append(execs, ex)
	}
	if err := rows.Err(); err != nil {
		return sm, nil, nil, err
	}

	tRows, err := s.db.Query(ctx,
		`SELECT id, session_id, target, status, error FROM scan_session_targets WHERE session_id = $1 ORDER BY target`, id)
	if err != nil {
		return sm, execs, nil, fmt.Errorf("scans: load targets: %w", err)
	}
	defer tRows.Close()
	var targets []sessionTarget
	for tRows.Next() {
		var t sessionTarget
		if err := tRows.Scan(&t.ID, &t.SessionID, &t.Target, &t.Status, &t.Error); err != nil {
			return sm, execs, nil, err
		}
		targets = append(targets, t)
	}
	return sm, execs, targets, tRows.Err()
}

// sessionTarget mirrors scan_session_targets.
type sessionTarget struct {
	ID        uuid.UUID `json:"id"`
	SessionID uuid.UUID `json:"session_id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Error     string    `json:"error"`
}

// scannerBinding pairs a scanner name with its execution config.
type scannerBinding struct {
	scanner string
	config  json.RawMessage
}

// scanSessionDetail is the GET /scans/{id} response.
type scanSessionDetail struct {
	models.ScanSession
	SessionTargets []sessionTarget `json:"session_targets"`
}

// ── request/response DTOs ───────────────────────────────────────────────

// ScannerConfigRequest binds one scanner and its configuration.
type ScannerConfigRequest struct {
	Scanner string          `json:"scanner"`
	Config  json.RawMessage `json:"config"`
}

// CreateRequest is the POST /projects/{id}/scans body. Either
// scanner_configs or profile_id must be supplied.
type CreateRequest struct {
	Name           string                 `json:"name"`
	Targets        []string               `json:"targets"`
	ScannerConfigs []ScannerConfigRequest `json:"scanner_configs"`
	ProfileID      *uuid.UUID             `json:"profile_id"`
}

// revalidateTargets re-applies the target bounds after profile substitution
// (SEC-008: targets arriving via a profile must not bypass request limits).
func (c *CreateRequest) revalidateTargets() error {
	if len(c.Targets) == 0 || len(c.Targets) > 500 {
		return errors.New("profile targets must number 1-500 entries")
	}
	for _, t := range c.Targets {
		if t == "" || len(t) > 253 {
			return errors.New("each profile target must be 1-253 characters")
		}
	}
	return nil
}

// validate normalizes and bounds the create request.
func (c *CreateRequest) validate() error {
	if len(c.Targets) == 0 || len(c.Targets) > 500 {
		return errors.New("targets must contain 1-500 entries")
	}
	for _, t := range c.Targets {
		if t == "" || len(t) > 253 {
			return errors.New("each target must be 1-253 characters")
		}
	}
	if (len(c.ScannerConfigs) == 0) == (c.ProfileID == nil) {
		return errors.New("exactly one of scanner_configs or profile_id must be supplied")
	}
	if len(c.ScannerConfigs) > 20 {
		return errors.New("at most 20 scanner_configs are allowed")
	}
	seen := map[string]bool{}
	for i := range c.ScannerConfigs {
		sc := &c.ScannerConfigs[i]
		if sc.Scanner == "" {
			return errors.New("scanner_configs[].scanner is required")
		}
		if seen[sc.Scanner] {
			return fmt.Errorf("duplicate scanner %q in scanner_configs", sc.Scanner)
		}
		seen[sc.Scanner] = true
		if len(sc.Config) == 0 {
			sc.Config = json.RawMessage(`{}`)
		}
	}
	if len(c.Name) > 200 {
		return errors.New("name too long")
	}
	return nil
}

// ── handlers: scanners ──────────────────────────────────────────────────

func (s *Service) listScanners(w http.ResponseWriter, r *http.Request) {
	recs, err := s.reg.List(r.Context())
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot list scanners")
		return
	}
	api.WriteList(w, recs, len(recs))
}

func (s *Service) getScanner(w http.ResponseWriter, r *http.Request) {
	rec, err := s.reg.GetRecord(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		api.WriteError(w, http.StatusNotFound, "scanner not found")
		return
	}
	api.WriteJSON(w, http.StatusOK, rec)
}

func (s *Service) setScannerEnabled(w http.ResponseWriter, r *http.Request) {
	idOrName := chi.URLParam(r, "id")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	rec, err := s.reg.GetRecord(r.Context(), idOrName)
	if err != nil {
		api.WriteError(w, http.StatusNotFound, "scanner not found")
		return
	}
	if body.Enabled {
		err = s.reg.Enable(r.Context(), rec.Name)
	} else {
		err = s.reg.Disable(r.Context(), rec.Name)
	}
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot update scanner")
		return
	}
	rec.Enabled = body.Enabled
	api.WriteJSON(w, http.StatusOK, rec)
}

func (s *Service) checkScanner(w http.ResponseWriter, r *http.Request) {
	idOrName := chi.URLParam(r, "id")
	rec, err := s.reg.GetRecord(r.Context(), idOrName)
	if err != nil {
		api.WriteError(w, http.StatusNotFound, "scanner not found")
		return
	}
	fresh, err := s.reg.CheckAvailability(r.Context(), rec.Name)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "availability check failed")
		return
	}
	api.WriteJSON(w, http.StatusOK, fresh)
}

// ── handlers: sessions ──────────────────────────────────────────────────

func (s *Service) createScan(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	var req CreateRequest
	if err := api.DecodeJSON(r, &req); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if err := req.validate(); err != nil {
		api.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	var exists bool
	if err := s.db.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)`, projectID).Scan(&exists); err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot verify project")
		return
	}
	if !exists {
		api.WriteError(w, http.StatusNotFound, "project not found")
		return
	}

	var bindings []scannerBinding
	if req.ProfileID != nil {
		bindings, err = s.profileBindings(r.Context(), *req.ProfileID, projectID)
		if err != nil {
			api.WriteError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		profileTargets, err := s.profileTargets(r.Context(), *req.ProfileID, projectID)
		if err != nil {
			api.WriteError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		if len(profileTargets) > 0 {
			req.Targets = profileTargets
			// SECURITY (SEC-008): profile-supplied targets replace the
			// request list after validation — re-apply the same bounds.
			if err := req.revalidateTargets(); err != nil {
				api.WriteError(w, http.StatusUnprocessableEntity, err.Error())
				return
			}
		}
	} else {
		for _, sc := range req.ScannerConfigs {
			bindings = append(bindings, scannerBinding{sc.Scanner, sc.Config})
		}
	}

	// Defense-in-depth: enforce the project scope allowlist at creation,
	// not only at execution. Unauthorized or excluded targets are refused.
	if err := s.orch.ValidateTargets(r.Context(), projectID, req.Targets); err != nil {
		api.WriteError(w, http.StatusBadRequest, "target not authorized: "+err.Error())
		return
	}

	// Every scanner must be registered and enabled at creation time, and
	// its configuration must satisfy the manifest schema (DEF-2: refuse
	// unknown keys and out-of-allowlist values with 422 up front rather
	// than discovering them when the doomed execution fails asynchronously).
	names := make([]string, 0, len(bindings))
	for _, b := range bindings {
		if !s.reg.Enabled(b.scanner) {
			api.WriteError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("scanner %q is not registered and enabled", b.scanner))
			return
		}
		if m, ok := s.reg.Manifest(b.scanner); ok && len(b.config) > 0 {
			var cfg scanners.ScannerConfig
			if err := json.Unmarshal(b.config, &cfg); err != nil {
				api.WriteError(w, http.StatusUnprocessableEntity,
					fmt.Sprintf("scanner %q: invalid config JSON: %v", b.scanner, err))
				return
			}
			if err := manifest.ValidateConfig(m.Configuration.Options, cfg); err != nil {
				api.WriteError(w, http.StatusUnprocessableEntity,
					fmt.Sprintf("scanner %q: %v", b.scanner, err))
				return
			}
		}
		names = append(names, b.scanner)
	}

	var createdBy *uuid.UUID
	if u := api.UserFromContext(r.Context()); u != nil {
		createdBy = &u.ID
	}

	var sessionID uuid.UUID
	err = s.db.InTx(r.Context(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO scan_sessions (project_id, profile_id, name, status, targets, scanner_names, created_by)
			VALUES ($1,$2,$3,'draft',$4,$5,$6) RETURNING id`,
			projectID, req.ProfileID, req.Name, req.Targets, names, createdBy,
		).Scan(&sessionID); err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		for _, t := range req.Targets {
			if _, err := tx.Exec(r.Context(), `
				INSERT INTO scan_session_targets (session_id, target, status) VALUES ($1,$2,'pending')`,
				sessionID, t); err != nil {
				return fmt.Errorf("insert session target: %w", err)
			}
		}
		for _, b := range bindings {
			if _, err := tx.Exec(r.Context(), `
				INSERT INTO scanner_executions (session_id, scanner_name, status, config, targets)
				VALUES ($1,$2,'queued',$3,$4)`,
				sessionID, b.scanner, b.config, req.Targets); err != nil {
				return fmt.Errorf("insert execution: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot create scan session")
		return
	}

	sm, execs, targets, err := s.getSession(r.Context(), sessionID)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot load created session")
		return
	}
	sm.Executions = execs
	api.WriteJSON(w, http.StatusCreated, scanSessionDetail{sm, targets})
}

func (s *Service) listScans(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	rows, err := s.db.Query(r.Context(),
		`SELECT `+sessionColumns+` FROM scan_sessions WHERE project_id = $1
		 ORDER BY created_at DESC LIMIT 200`, projectID)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot list scans")
		return
	}
	defer rows.Close()
	var items []models.ScanSession
	for rows.Next() {
		sm, err := scanSession(rows)
		if err != nil {
			api.WriteError(w, http.StatusInternalServerError, "cannot list scans")
			return
		}
		items = append(items, sm)
	}
	if err := rows.Err(); err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot list scans")
		return
	}
	var total int
	_ = s.db.QueryRow(r.Context(),
		`SELECT count(*) FROM scan_sessions WHERE project_id = $1`, projectID).Scan(&total)
	api.WriteList(w, items, total)
}

func (s *Service) getScan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	sm, execs, targets, err := s.getSession(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		api.WriteError(w, http.StatusNotFound, "scan session not found")
		return
	}
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot load scan session")
		return
	}
	sm.Executions = execs
	api.WriteJSON(w, http.StatusOK, scanSessionDetail{sm, targets})
}

// startScan queues and asynchronously runs a session. Only
// draft/queued/cancelled sessions may start.
func (s *Service) startScan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	var status string
	err = s.db.QueryRow(r.Context(),
		`SELECT status FROM scan_sessions WHERE id = $1`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		api.WriteError(w, http.StatusNotFound, "scan session not found")
		return
	}
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot load scan session")
		return
	}
	switch status {
	case models.ScanStatusDraft, models.ScanStatusQueued, models.ScanStatusCancelled:
	default:
		api.WriteError(w, http.StatusConflict,
			fmt.Sprintf("cannot start a session in status %q (only draft, queued or cancelled)", status))
		return
	}

	// Retry semantics when restarting a cancelled session: queued/failed/cancelled
	// executions become queued again; completed ones are kept.
	if status == models.ScanStatusCancelled {
		if _, err := s.db.Exec(r.Context(), `
			UPDATE scanner_executions
			SET status = 'queued', error = '', started_at = NULL, finished_at = NULL
			WHERE session_id = $1 AND status IN ('queued','failed','cancelled')`, id); err != nil {
			api.WriteError(w, http.StatusInternalServerError, "cannot reset executions")
			return
		}
	}

	var queued bool
	err = s.db.QueryRow(r.Context(), `
		UPDATE scan_sessions
		SET status = 'queued', error = '', updated_at = now()
		WHERE id = $1 AND status IN ('draft','queued','cancelled')
		RETURNING true`, id).Scan(&queued)
	if errors.Is(err, pgx.ErrNoRows) {
		api.WriteError(w, http.StatusConflict, "session status changed concurrently; retry")
		return
	}
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot queue session")
		return
	}

	if err := s.orch.StartSession(r.Context(), id); err != nil {
		// Roll back to queued so the client can retry.
		_, _ = s.db.Exec(context.Background(),
			`UPDATE scan_sessions SET status = 'queued', error = $2, updated_at = now() WHERE id = $1 AND status = 'running'`,
			id, err.Error())
		api.WriteError(w, http.StatusConflict, err.Error())
		return
	}

	sm, execs, targets, err := s.getSession(context.Background(), id)
	if err != nil {
		api.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "status": models.ScanStatusRunning})
		return
	}
	sm.Executions = execs
	api.WriteJSON(w, http.StatusAccepted, scanSessionDetail{sm, targets})
}

// cancelScan requests cancellation. Running sessions are cancelled through
// the orchestrator; queued/draft sessions are marked cancelled directly.
func (s *Service) cancelScan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	var status string
	err = s.db.QueryRow(r.Context(), `SELECT status FROM scan_sessions WHERE id = $1`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		api.WriteError(w, http.StatusNotFound, "scan session not found")
		return
	}
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot load scan session")
		return
	}
	switch status {
	case models.ScanStatusDraft, models.ScanStatusQueued, models.ScanStatusRunning:
	default:
		api.WriteError(w, http.StatusConflict, fmt.Sprintf("session is %q, nothing to cancel", status))
		return
	}

	if status == models.ScanStatusRunning && !s.orch.Cancel(id) {
		// Not running in this process (e.g. after a restart): force-cancel.
		if _, err := s.db.Exec(r.Context(), `
			UPDATE scan_sessions SET status='cancelled', finished_at = now(), updated_at = now()
			WHERE id = $1 AND status = 'running'`, id); err != nil {
			api.WriteError(w, http.StatusInternalServerError, "cannot cancel session")
			return
		}
		_, _ = s.db.Exec(r.Context(), `
			UPDATE scanner_executions SET status='cancelled', finished_at = now()
			WHERE session_id = $1 AND status IN ('queued','running')`, id)
	} else if status != models.ScanStatusRunning {
		if _, err := s.db.Exec(r.Context(), `
			UPDATE scan_sessions SET status='cancelled', finished_at = now(), updated_at = now()
			WHERE id = $1 AND status IN ('draft','queued')`, id); err != nil {
			api.WriteError(w, http.StatusInternalServerError, "cannot cancel session")
			return
		}
	}

	sm, execs, targets, err := s.getSession(r.Context(), id)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot load scan session")
		return
	}
	sm.Executions = execs
	api.WriteJSON(w, http.StatusOK, scanSessionDetail{sm, targets})
}

// ── profile resolution ──────────────────────────────────────────────────

func (s *Service) profileBindings(ctx context.Context, profileID, projectID uuid.UUID) ([]scannerBinding, error) {
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM scan_profiles WHERE id = $1 AND project_id = $2)`,
		profileID, projectID).Scan(&exists); err != nil || !exists {
		return nil, fmt.Errorf("profile not found in this project")
	}
	rows, err := s.db.Query(ctx, `
		SELECT s.name, ps.config
		FROM scan_profile_scanners ps
		JOIN scanners s ON s.id = ps.scanner_id
		WHERE ps.profile_id = $1
		ORDER BY ps.sort_order, s.name`, profileID)
	if err != nil {
		return nil, fmt.Errorf("cannot load profile scanners: %w", err)
	}
	defer rows.Close()
	var out []scannerBinding
	for rows.Next() {
		var b scannerBinding
		if err := rows.Scan(&b.scanner, &b.config); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Service) profileTargets(ctx context.Context, profileID, projectID uuid.UUID) ([]string, error) {
	var selection, excluded []string
	if err := s.db.QueryRow(ctx,
		`SELECT target_selection, excluded_targets FROM scan_profiles WHERE id = $1`,
		profileID).Scan(&selection, &excluded); err != nil {
		return nil, fmt.Errorf("cannot load profile: %w", err)
	}
	excludedSet := map[string]bool{}
	for _, e := range excluded {
		excludedSet[e] = true
	}

	candidates := selection
	if len(selection) == 0 {
		rows, err := s.db.Query(ctx, `
			SELECT target FROM project_targets
			WHERE project_id = $1 AND excluded = false ORDER BY target`, projectID)
		if err != nil {
			return nil, fmt.Errorf("cannot load project targets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var t string
			if err := rows.Scan(&t); err != nil {
				return nil, err
			}
			candidates = append(candidates, t)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	var out []string
	for _, t := range candidates {
		if !excludedSet[t] {
			out = append(out, t)
		}
	}
	return out, nil
}

// ── SSE ─────────────────────────────────────────────────────────────────

// heartbeatInterval matches the contract's 25s server heartbeat.
const heartbeatInterval = 25 * time.Second

// streamEvents streams scan/execution events for one session.
// Each event uses the wire contract: `event: <topic>` + `data: <payload>`.
func (s *Service) streamEvents(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		api.WriteError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	var exists bool
	if err := s.db.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM scan_sessions WHERE id = $1)`, id).Scan(&exists); err != nil || !exists {
		api.WriteError(w, http.StatusNotFound, "scan session not found")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Initial snapshot event so late subscribers sync immediately.
	if sm, _, _, err := s.getSession(r.Context(), id); err == nil {
		writeSSE(w, flusher, "scan", orchestrationPayload{
			"session_id": sm.ID.String(), "status": sm.Status,
		})
	}

	ch, unsub := s.bus.Subscribe()
	defer unsub()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				// The bus closed this channel — either a slow-consumer
				// eviction (SEC-012) or an over-capacity handout. Receiving
				// from a closed channel always succeeds, so without this
				// exit the loop would spin at 100% CPU until the client
				// (possibly the very stalled attacker that triggered the
				// eviction) chose to disconnect. End the stream; the SSE
				// client sees EOF and reconnects.
				return
			}
			if !eventBelongsToSession(ev, idStr) {
				continue
			}
			writeSSE(w, flusher, ev.Topic, ev.Payload)
		}
	}
}

// orchestrationPayload is a convenience map alias for synthetic events.
type orchestrationPayload map[string]any

func writeSSE(w http.ResponseWriter, flusher http.Flusher, topic string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", topic, data)
	flusher.Flush()
}

// eventBelongsToSession matches events whose payload carries the session id.
// Execution and progress events carry session_id, so the filter is uniform.
func eventBelongsToSession(ev events.Event, sessionID string) bool {
	data, err := json.Marshal(ev.Payload)
	if err != nil {
		return false
	}
	var probe struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.SessionID == sessionID
}
