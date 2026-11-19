package reports

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/audit"
	"github.com/mauropm/wadjet/internal/config"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
	"github.com/mauropm/wadjet/internal/models"
)

// maxConcurrentGenerations bounds how many reports render in parallel
// (worker pool semaphore size).
const maxConcurrentGenerations = 2

// generationTimeout bounds a single report rendering job.
const generationTimeout = 10 * time.Minute

// Service owns the report lifecycle: creation, asynchronous generation,
// persistence on disk and the REST surface. It satisfies api.Registrable.
type Service struct {
	db    *database.DB
	cfg   *config.Config
	bus   *events.Bus
	audit *audit.Logger

	sem chan struct{} // worker pool semaphore (N = maxConcurrentGenerations)
	wg  sync.WaitGroup

	// scopes snapshots the finding filter chosen at request time so the
	// worker reproduces the exact scope. Queues are in-process; rows that
	// survive a restart are failed by recoverStale, so an in-memory map is
	// consistent with the persistence model.
	mu     sync.Mutex
	scopes map[uuid.UUID]findingFilter
}

// NewService creates the reports service. Wire it into the API server via
// the api.Registrable list in cmd/server.
func NewService(db *database.DB, cfg *config.Config, bus *events.Bus, auditLogger *audit.Logger) *Service {
	s := &Service{
		db:     db,
		cfg:    cfg,
		bus:    bus,
		audit:  auditLogger,
		sem:    make(chan struct{}, maxConcurrentGenerations),
		scopes: map[uuid.UUID]findingFilter{},
	}
	// Reports already completed before a restart stay downloadable from
	// disk; rows stuck in pending/generating were interrupted and are
	// marked failed so clients can retry.
	go s.recoverStale()
	return s
}

// Wait blocks until all queued generation jobs have finished. Used by tests
// and available for graceful shutdown.
func (s *Service) Wait() { s.wg.Wait() }

// recoverStale fails report rows left mid-flight by a previous process.
func (s *Service) recoverStale() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tag, err := s.db.Exec(ctx,
		`UPDATE reports SET status = 'failed', error = 'generation interrupted by server restart'
		 WHERE status IN ('pending','generating')`)
	if err != nil {
		log.Printf("reports: stale report recovery failed: %v", err)
		return
	}
	if tag.RowsAffected() > 0 {
		log.Printf("reports: marked %d stale report(s) failed after restart", tag.RowsAffected())
	}
}

// publish relays the SSE contract: topic "report", kind "report.status",
// payload {report_id, project_id, status, file_size}.
func (s *Service) publish(r models.Report) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(events.Event{
		Topic: "report",
		Kind:  "report.status",
		Payload: map[string]any{
			"report_id":  r.ID,
			"project_id": r.ProjectID,
			"status":     r.Status,
			"file_size":  r.FileSize,
		},
	})
}

// ───────────────────────────────────────────── creation & queue

// rememberScope snapshots a finding filter for the queued generation job.
func (s *Service) rememberScope(id uuid.UUID, flt findingFilter) {
	s.mu.Lock()
	s.scopes[id] = flt
	s.mu.Unlock()
}

func (s *Service) takeScope(id uuid.UUID) findingFilter {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopes[id] // zero value when absent (unfiltered project scope)
}

// createReport inserts a pending row and schedules generation. It returns
// immediately with the pending entity; the worker transitions the row
// through generating → completed/failed.
func (s *Service) createReport(r models.Report, flt *findingFilter) (models.Report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := s.db.QueryRow(ctx,
		`INSERT INTO reports (project_id, session_id, finding_id, type, status)
		 VALUES ($1, $2, $3, $4, 'pending')
		 RETURNING id, project_id, session_id, finding_id, type, status,
		           file_path, file_size, error, created_at, completed_at`,
		r.ProjectID, r.SessionID, r.FindingID, r.Type).
		Scan(&r.ID, &r.ProjectID, &r.SessionID, &r.FindingID, &r.Type, &r.Status,
			&r.FilePath, &r.FileSize, &r.Error, &r.CreatedAt, &r.CompletedAt)
	if err != nil {
		return r, fmt.Errorf("insert report: %w", err)
	}
	if flt != nil {
		s.rememberScope(r.ID, *flt) // must precede scheduling
	}
	s.publish(r)
	s.schedule(r.ID)
	return r, nil
}

// schedule queues a generation job on the bounded worker pool.
func (s *Service) schedule(reportID uuid.UUID) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sem <- struct{}{} // acquire
		defer func() { <-s.sem }()
		s.generate(reportID)
	}()
}

// generate renders one report to disk and records the outcome.
func (s *Service) generate(reportID uuid.UUID) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("reports: panic while generating %s: %v", reportID, p)
			s.markFailed(reportID, fmt.Sprintf("internal panic: %v", p))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), generationTimeout)
	defer cancel()

	rpt, err := s.getReport(ctx, reportID)
	if err != nil {
		log.Printf("reports: generation aborted for %s: %v", reportID, err)
		return
	}
	// Re-open any row still queued; ignore rows already finalized.
	if n, err := s.db.Exec(ctx,
		`UPDATE reports SET status='generating' WHERE id=$1 AND status IN ('pending','generating')`, reportID); err != nil {
		log.Printf("reports: cannot mark generating %s: %v", reportID, err)
		return
	} else if n.RowsAffected() == 0 {
		return
	}
	rpt.Status = models.ReportStatusGenerating
	s.publish(rpt)

	var (
		data []byte
		ext  = ".pdf"
	)
	switch rpt.Type {
	case models.ReportTypeScan:
		if rpt.SessionID == nil {
			s.markFailed(reportID, "scan report is missing its session reference")
			return
		}
		data, err = s.renderScanReport(ctx, rpt.ProjectID, *rpt.SessionID)
	case models.ReportTypeFinding:
		if rpt.FindingID == nil {
			s.markFailed(reportID, "finding report is missing its finding reference")
			return
		}
		data, _, err = s.findingAdvisory(ctx, *rpt.FindingID)
	case models.ReportTypeFindingsConsolidated:
		data, err = s.consolidatedReport(ctx, rpt.ProjectID, s.takeScope(reportID))
	case models.ReportTypeFindingsZip:
		ext = ".zip"
		data, err = s.findingsZip(ctx, rpt.ProjectID, s.takeScope(reportID))
	default:
		err = fmt.Errorf("unknown report type %q", rpt.Type)
	}
	if err != nil {
		s.markFailed(reportID, err.Error())
		return
	}

	relPath, err := s.writeArtifact(rpt, data, ext)
	if err != nil {
		s.markFailed(reportID, err.Error())
		return
	}

	now := time.Now().UTC()
	var size int64 = int64(len(data))
	if st, serr := os.Stat(filepath.Join(s.cfg.ReportDir, relPath)); serr == nil {
		size = st.Size()
	}
	if _, err := s.db.Exec(ctx,
		`UPDATE reports SET status='completed', file_path=$2, file_size=$3, error='', completed_at=$4
		 WHERE id=$1`, reportID, relPath, size, now); err != nil {
		log.Printf("reports: cannot mark completed %s: %v", reportID, err)
		return
	}
	rpt.Status = models.ReportStatusCompleted
	rpt.FilePath = relPath
	rpt.FileSize = size
	rpt.CompletedAt = &now
	s.publish(rpt)
}

// writeArtifact persists rendered bytes under the report directory and
// returns the path relative to it:
// <project-slug>/<type>-<report-uuid>-<yyyymmdd-hhmm><ext>
func (s *Service) writeArtifact(rpt models.Report, data []byte, ext string) (string, error) {
	slug, err := s.projectSlug(context.Background(), rpt)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s-%s%s", rpt.Type, rpt.ID.String(), time.Now().UTC().Format("20060102-1504"), ext)
	rel := filepath.ToSlash(filepath.Join(slug, name))
	if !isPathSafe(rel) {
		return "", fmt.Errorf("unsafe report path %q", rel)
	}
	abs := filepath.Join(s.cfg.ReportDir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return "", fmt.Errorf("create report dir: %w", err)
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("finalize report: %w", err)
	}
	return rel, nil
}

// projectSlug resolves the directory name for a report's project.
func (s *Service) projectSlug(ctx context.Context, rpt models.Report) (string, error) {
	name := "project"
	if p, err := loadProject(ctx, s.db, rpt.ProjectID); err == nil {
		name = p.Name
	} else if errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("%w: project %s no longer exists", ErrNotFound, rpt.ProjectID)
	} else {
		return "", err
	}
	return slugify(name), nil
}

// markFailed records a generation failure.
func (s *Service) markFailed(reportID uuid.UUID, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reason = capText(sanitizeText(reason), 2000)
	rpt, err := s.getReport(ctx, reportID)
	if err != nil {
		return
	}
	if _, err := s.db.Exec(ctx,
		`UPDATE reports SET status='failed', error=$2, completed_at=$3 WHERE id=$1`,
		reportID, reason, time.Now().UTC()); err != nil {
		log.Printf("reports: cannot mark failed %s: %v", reportID, err)
		return
	}
	rpt.Status = models.ReportStatusFailed
	rpt.Error = reason
	s.publish(rpt)
}

// ───────────────────────────────────────────── reads

func (s *Service) getReport(ctx context.Context, id uuid.UUID) (models.Report, error) {
	var r models.Report
	err := s.db.QueryRow(ctx,
		`SELECT id, project_id, session_id, finding_id, type, status, file_path, file_size,
		        error, created_at, completed_at
		 FROM reports WHERE id = $1`, id).
		Scan(&r.ID, &r.ProjectID, &r.SessionID, &r.FindingID, &r.Type, &r.Status,
			&r.FilePath, &r.FileSize, &r.Error, &r.CreatedAt, &r.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// listReports returns reports newest-first, optionally scoped to a project
// and filtered by type.
func (s *Service) listReports(ctx context.Context, projectID *uuid.UUID, typ string, limit int) ([]models.Report, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, project_id, session_id, finding_id, type, status, file_path, file_size,
	             error, created_at, completed_at
	      FROM reports WHERE 1=1`
	args := []any{}
	n := 0
	if projectID != nil {
		n++
		q += fmt.Sprintf(` AND project_id = $%d`, n)
		args = append(args, *projectID)
	}
	if typ != "" {
		n++
		q += fmt.Sprintf(` AND type = $%d`, n)
		args = append(args, typ)
	}
	var total int
	countQ := `SELECT count(*) FROM reports WHERE 1=1`
	if projectID != nil {
		countQ += ` AND project_id = $1`
	}
	if typ != "" {
		if projectID != nil {
			countQ += ` AND type = $2`
		} else {
			countQ += ` AND type = $1`
		}
	}
	if err := s.db.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q += ` ORDER BY created_at DESC, id LIMIT $` + fmt.Sprint(n+1)
	args = append(args, limit)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []models.Report
	for rows.Next() {
		var r models.Report
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.SessionID, &r.FindingID, &r.Type, &r.Status,
			&r.FilePath, &r.FileSize, &r.Error, &r.CreatedAt, &r.CompletedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// verifyChain enforces project isolation: the report's session and finding
// references must still resolve to rows owned by the report's project.
// Cross-project or dangling references are treated as not found.
func (s *Service) verifyChain(ctx context.Context, r models.Report) error {
	if r.SessionID != nil {
		var owner uuid.UUID
		err := s.db.QueryRow(ctx, `SELECT project_id FROM scan_sessions WHERE id = $1`, *r.SessionID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != r.ProjectID) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
	}
	if r.FindingID != nil {
		var owner uuid.UUID
		err := s.db.QueryRow(ctx, `SELECT project_id FROM findings WHERE id = $1`, *r.FindingID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != r.ProjectID) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ───────────────────────────────────────────── HTTP

// Register mounts the report endpoints. r is already mounted under /api/v1
// behind authentication (CONTRACTS.md §2).
func (s *Service) Register(r chi.Router) {
	r.Post("/projects/{id}/reports/scan", s.handleCreateScanReport)
	r.Post("/projects/{id}/reports/findings", s.handleCreateFindingsReport)
	r.Post("/findings/{id}/report", s.handleCreateFindingReport)
	r.Get("/reports", s.handleListReports)
	r.Get("/reports/{id}", s.handleGetReport)
	r.Get("/reports/{id}/download", s.handleDownload)
}

func (s *Service) userID(r *http.Request) *uuid.UUID {
	if u := api.UserFromContext(r.Context()); u != nil {
		return &u.ID
	}
	return nil
}

func pathUUID(r *http.Request, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, param))
	return id, err == nil
}

func (s *Service) handleCreateScanReport(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(r, "id")
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sessionID, err := uuid.Parse(body.SessionID)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "session_id is required and must be a UUID")
		return
	}
	ctx := r.Context()
	sess, err := loadSession(ctx, s.db, sessionID)
	if errors.Is(err, ErrNotFound) || (err == nil && sess.ProjectID != projectID) {
		api.WriteError(w, http.StatusNotFound, "scan session not found in this project")
		return
	}
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot load scan session")
		return
	}
	if _, err := loadProject(ctx, s.db, projectID); err != nil {
		api.WriteError(w, http.StatusNotFound, "project not found")
		return
	}
	rpt, err := s.createReport(models.Report{
		ProjectID: projectID, SessionID: &sessionID, Type: models.ReportTypeScan,
	}, nil)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot queue report")
		return
	}
	s.audit.LogRequest(r, s.userID(r), "report.create", "report", rpt.ID.String(),
		map[string]any{"type": rpt.Type, "session_id": sessionID})
	api.WriteJSON(w, http.StatusAccepted, rpt)
}

func (s *Service) handleCreateFindingsReport(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(r, "id")
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	var body struct {
		Consolidated bool     `json:"consolidated"`
		Severity     []string `json:"severity"`
		AssetID      string   `json:"asset_id"`
		SessionID    string   `json:"session_id"`
	}
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	flt := findingFilter{}
	for _, sev := range body.Severity {
		sev = strings.ToLower(strings.TrimSpace(sev))
		switch sev {
		case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
			models.SeverityLow, models.SeverityInfo:
			flt.Severities = append(flt.Severities, sev)
		default:
			api.WriteError(w, http.StatusBadRequest, "unknown severity "+sev)
			return
		}
	}
	ctx := r.Context()
	if body.AssetID != "" {
		assetID, err := uuid.Parse(body.AssetID)
		if err != nil {
			api.WriteError(w, http.StatusBadRequest, "asset_id must be a UUID")
			return
		}
		var owner uuid.UUID
		err = s.db.QueryRow(ctx, `SELECT project_id FROM assets WHERE id = $1`, assetID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != projectID) {
			api.WriteError(w, http.StatusNotFound, "asset not found in this project")
			return
		}
		if err != nil {
			api.WriteError(w, http.StatusInternalServerError, "cannot load asset")
			return
		}
		flt.AssetID = &assetID
	}
	if body.SessionID != "" {
		sessID, err := uuid.Parse(body.SessionID)
		if err != nil {
			api.WriteError(w, http.StatusBadRequest, "session_id must be a UUID")
			return
		}
		sess, err := loadSession(ctx, s.db, sessID)
		if errors.Is(err, ErrNotFound) || (err == nil && sess.ProjectID != projectID) {
			api.WriteError(w, http.StatusNotFound, "scan session not found in this project")
			return
		}
		if err != nil {
			api.WriteError(w, http.StatusInternalServerError, "cannot load scan session")
			return
		}
		flt.SessionID = &sessID
	}
	if _, err := loadProject(ctx, s.db, projectID); err != nil {
		api.WriteError(w, http.StatusNotFound, "project not found")
		return
	}
	matches, err := loadFindings(ctx, s.db, projectID, flt)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot evaluate findings scope")
		return
	}
	if len(matches) == 0 {
		api.WriteError(w, http.StatusUnprocessableEntity, "no findings match the requested scope")
		return
	}
	typ := models.ReportTypeFindingsZip
	if body.Consolidated {
		typ = models.ReportTypeFindingsConsolidated
	}
	rpt, err := s.createReport(models.Report{
		ProjectID: projectID, SessionID: flt.SessionID, Type: typ,
	}, &flt)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot queue report")
		return
	}
	s.audit.LogRequest(r, s.userID(r), "report.create", "report", rpt.ID.String(),
		map[string]any{"type": typ, "severity": flt.Severities, "asset_id": body.AssetID, "session_id": body.SessionID})
	api.WriteJSON(w, http.StatusAccepted, rpt)
}

func (s *Service) handleCreateFindingReport(w http.ResponseWriter, r *http.Request) {
	findingID, ok := pathUUID(r, "id")
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	ctx := r.Context()
	f, err := loadFinding(ctx, s.db, findingID)
	if errors.Is(err, ErrNotFound) {
		api.WriteError(w, http.StatusNotFound, "finding not found")
		return
	}
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot load finding")
		return
	}
	rpt, err := s.createReport(models.Report{
		ProjectID: f.ProjectID, FindingID: &findingID, Type: models.ReportTypeFinding,
	}, nil)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot queue report")
		return
	}
	s.audit.LogRequest(r, s.userID(r), "report.create", "report", rpt.ID.String(),
		map[string]any{"type": rpt.Type, "finding_id": findingID})
	api.WriteJSON(w, http.StatusAccepted, rpt)
}

func (s *Service) handleListReports(w http.ResponseWriter, r *http.Request) {
	var projectID *uuid.UUID
	if ps := r.URL.Query().Get("project_id"); ps != "" {
		id, err := uuid.Parse(ps)
		if err != nil {
			api.WriteError(w, http.StatusBadRequest, "project_id must be a UUID")
			return
		}
		projectID = &id
	}
	typ := r.URL.Query().Get("type")
	if typ != "" {
		switch typ {
		case models.ReportTypeScan, models.ReportTypeFinding,
			models.ReportTypeFindingsConsolidated, models.ReportTypeFindingsZip:
		default:
			api.WriteError(w, http.StatusBadRequest, "unknown report type")
			return
		}
	}
	items, total, err := s.listReports(r.Context(), projectID, typ, 0)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "cannot list reports")
		return
	}
	api.WriteList(w, items, total)
}

// resolveReportByID loads a report and enforces project isolation: an
// explicit ?project_id must match, and the report's session/finding links
// must resolve back to the report's project (chain validation). Anything
// off is reported as not found to avoid leaking cross-project existence.
func (s *Service) resolveReportByID(ctx context.Context, id uuid.UUID, scopeProject string) (models.Report, bool) {
	rpt, err := s.getReport(ctx, id)
	if err != nil {
		return models.Report{}, false
	}
	if scopeProject != "" {
		want, err := uuid.Parse(scopeProject)
		if err != nil || want != rpt.ProjectID {
			return models.Report{}, false
		}
	}
	if err := s.verifyChain(ctx, rpt); err != nil {
		return models.Report{}, false
	}
	return rpt, true
}

func (s *Service) handleGetReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "invalid report id")
		return
	}
	rpt, ok := s.resolveReportByID(r.Context(), id, r.URL.Query().Get("project_id"))
	if !ok {
		api.WriteError(w, http.StatusNotFound, "report not found")
		return
	}
	api.WriteJSON(w, http.StatusOK, rpt)
}

func (s *Service) handleDownload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		api.WriteError(w, http.StatusBadRequest, "invalid report id")
		return
	}
	rpt, ok := s.resolveReportByID(r.Context(), id, r.URL.Query().Get("project_id"))
	if !ok {
		api.WriteError(w, http.StatusNotFound, "report not found")
		return
	}
	if rpt.Status != models.ReportStatusCompleted {
		api.WriteError(w, http.StatusConflict, "report is not completed")
		return
	}
	if !isPathSafe(rpt.FilePath) {
		api.WriteError(w, http.StatusNotFound, "report file not found")
		return
	}
	abs := filepath.Join(s.cfg.ReportDir, filepath.FromSlash(rpt.FilePath))
	f, err := os.Open(abs)
	if err != nil {
		api.WriteError(w, http.StatusNotFound, "report file not found")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		api.WriteError(w, http.StatusNotFound, "report file not found")
		return
	}
	ctype := "application/pdf"
	if rpt.Type == models.ReportTypeFindingsZip {
		ctype = "application/zip"
	}
	name := fileSafe(filepath.Base(rpt.FilePath))
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
	s.audit.LogRequest(r, s.userID(r), "report.download", "report", rpt.ID.String(),
		map[string]any{"type": rpt.Type, "file_size": rpt.FileSize})
}
