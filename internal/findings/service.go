package findings

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
	"github.com/mauropm/wadjet/internal/assets"
	"github.com/mauropm/wadjet/internal/audit"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
)

// Errors returned by the finding queries and the status workflow.
var (
	// ErrNotFound means no finding row matches.
	ErrNotFound = errors.New("finding not found")
	// ErrConflict means an equivalent finding already exists.
	ErrConflict = errors.New("finding already exists")
	// ErrInvalidInput marks a malformed request or an unknown status.
	ErrInvalidInput = errors.New("invalid finding input")
)

// Service implements scanners.ResultSink and the finding HTTP surface.
type Service struct {
	db     *database.DB
	assets *assets.Service
	audit  *audit.Logger
}

// NewService builds the finding service. assetsSvc owns the identity rules and
// the asset upserts that ingestion depends on, so both layers always agree on
// what an asset is. auditLogger may be nil.
func NewService(db *database.DB, assetsSvc *assets.Service, auditLogger *audit.Logger) *Service {
	if assetsSvc == nil {
		assetsSvc = assets.NewService(db)
	}
	return &Service{db: db, assets: assetsSvc, audit: auditLogger}
}

// Register mounts the finding routes on the /api/v1 router.
func (s *Service) Register(r chi.Router) {
	r.Get("/projects/{id}/findings", s.handleList)
	r.Post("/projects/{id}/findings", s.handleCreate)
	r.Get("/findings/{id}", s.handleGet)
	r.Put("/findings/{id}/status", s.handleStatus)
	r.Get("/findings/{id}/history", s.handleHistory)
}

// Compile-time proof that the orchestrator's contract is satisfied: the
// findings service really is the ResultSink the scan engine writes into.
var _ scanners.ResultSink = (*Service)(nil)

// ───────────────────────────────────────────── queries

// Filters narrows the project finding list.
type Filters struct {
	Severity string
	Status   string
	Scanner  string
	AssetID  *uuid.UUID
	Query    string // ILIKE over title and description
	Sort     string
	Desc     bool
	Limit    int
	Offset   int
}

// List returns the findings of a project plus the total match count.
func (s *Service) List(ctx context.Context, projectID uuid.UUID, f Filters) ([]models.Finding, int, error) {
	var conds []string
	var args []any
	args = append(args, projectID)
	conds = append(conds, "project_id = $1")
	add := func(cond string, arg any) {
		base := len(args)
		n := strings.Count(cond, "?")
		for i := 0; i < n; i++ {
			cond = strings.Replace(cond, "?", fmt.Sprintf("$%d", base+i+1), 1)
			args = append(args, arg)
		}
		conds = append(conds, cond)
	}
	if f.Severity != "" {
		if !validSeverity(f.Severity) {
			return nil, 0, fmt.Errorf("%w: unknown severity %q", ErrInvalidInput, f.Severity)
		}
		add("severity = ?", f.Severity)
	}
	if f.Status != "" {
		if !validStatus(f.Status) {
			return nil, 0, fmt.Errorf("%w: unknown status %q", ErrInvalidInput, f.Status)
		}
		add("status = ?", f.Status)
	}
	if f.Scanner != "" {
		add("scanner = ?", f.Scanner)
	}
	if f.AssetID != nil {
		add("asset_id = ?", *f.AssetID)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + escapeLike(q) + "%"
		add("(title ILIKE ? OR description ILIKE ?)", like)
	}

	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM findings WHERE `+strings.Join(conds, " AND "), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	orderBy, ok := findingSort(f.Sort, f.Desc)
	if !ok {
		return nil, 0, fmt.Errorf("%w: unknown sort %q", ErrInvalidInput, f.Sort)
	}
	args = append(args, clampInt(f.Limit, 100, 1, 1000), clampInt(f.Offset, 0, 0, 1<<31-1))
	rows, err := s.db.Query(ctx,
		`SELECT `+findingCols+` FROM findings WHERE `+strings.Join(conds, " AND ")+` ORDER BY `+orderBy+
			fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []models.Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

// Get loads one finding.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Finding, error) {
	f, err := scanFinding(s.db.QueryRow(ctx, `SELECT `+findingCols+` FROM findings WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &f, nil
}

// StatusHistory returns the status transitions of a finding, newest first.
func (s *Service) StatusHistory(ctx context.Context, findingID uuid.UUID) ([]models.FindingStatusHistory, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, finding_id, from_status, to_status, changed_by, note, created_at
		   FROM finding_status_history WHERE finding_id = $1
		  ORDER BY created_at DESC, id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.FindingStatusHistory{}
	for rows.Next() {
		var h models.FindingStatusHistory
		if err := rows.Scan(&h.ID, &h.FindingID, &h.FromStatus, &h.ToStatus, &h.ChangedBy, &h.Note, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Observations returns the detection history of a finding, newest first.
func (s *Service) Observations(ctx context.Context, findingID uuid.UUID, limit int) ([]models.FindingObservation, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, finding_id, scan_session_id, scanner_execution_id, observed_at, status_at_detection, raw, created_at
		   FROM finding_observations WHERE finding_id = $1
		  ORDER BY observed_at DESC, created_at DESC, id DESC LIMIT $2`, findingID, clampInt(limit, 100, 1, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.FindingObservation{}
	for rows.Next() {
		var o models.FindingObservation
		if err := rows.Scan(&o.ID, &o.FindingID, &o.ScanSessionID, &o.ScannerExecutionID,
			&o.ObservedAt, &o.StatusAtDetection, &o.Raw, &o.CreatedAt); err != nil {
			return nil, err
		}
		if len(o.Raw) == 0 {
			o.Raw = json.RawMessage(`{}`)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// FindingHistory is the full audit trail of one finding.
type FindingHistory struct {
	StatusHistory []models.FindingStatusHistory `json:"status_history"`
	Observations  []models.FindingObservation   `json:"observations"`
}

// History combines both histories; either may be empty, never nil in JSON.
func (s *Service) History(ctx context.Context, findingID uuid.UUID) (*FindingHistory, error) {
	if _, err := s.Get(ctx, findingID); err != nil {
		return nil, err
	}
	status, err := s.StatusHistory(ctx, findingID)
	if err != nil {
		return nil, err
	}
	obs, err := s.Observations(ctx, findingID, 500)
	if err != nil {
		return nil, err
	}
	return &FindingHistory{StatusHistory: status, Observations: obs}, nil
}

// ───────────────────────────────────────────── status workflow

// validStatus mirrors the findings.status CHECK constraint.
func validStatus(s string) bool {
	switch s {
	case models.FindingStatusOpen, models.FindingStatusConfirmed, models.FindingStatusRemediated,
		models.FindingStatusAcceptedRisk, models.FindingStatusFalsePositive:
		return true
	default:
		return false
	}
}

func validSeverity(s string) bool {
	switch s {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo:
		return true
	default:
		return false
	}
}

// UpdateStatus moves a finding to a new analyst status, appends a
// finding_status_history row and writes an audit entry.
//
// Transition policy
//
//	The workflow is deliberately non-linear: any defined status may move to any
//	other defined status. Assessments iterate, and an assessor must be able to
//	reverse a click without support intervention — so remediated, accepted_risk
//	and false_positive are not terminal. What is enforced:
//
//	  - the destination must be one of the five defined statuses, so a typo can
//	    never reach the CHECK constraint as a 500;
//	  - every transition is recorded in finding_status_history with the acting
//	    user and the note, and in the audit log;
//	  - moving into 'remediated' through this API is allowed, and precisely
//	    because it is an assessor claim rather than proof, it is audited and it
//	    is the one state a later scanner detection may reverse on its own (see
//	    the policy documented on Ingest).
//
// Re-applying the current status is allowed and still recorded, which keeps the
// history a faithful log of what the analyst did.
func (s *Service) UpdateStatus(ctx context.Context, id uuid.UUID, status, note string, changedBy *uuid.UUID) (*models.Finding, error) {
	if !validStatus(status) {
		return nil, fmt.Errorf("%w: unknown status %q", ErrInvalidInput, status)
	}
	// finding_status_history.changed_by has a foreign key to users: check it
	// here so a stale session yields a clear 400 instead of a constraint
	// violation surfacing as a 500. The key still guards the race.
	if changedBy != nil {
		var known bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, *changedBy).Scan(&known); err != nil {
			return nil, err
		}
		if !known {
			return nil, fmt.Errorf("%w: unknown user %s", ErrInvalidInput, changedBy)
		}
	}
	var out *models.Finding
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		current, err := scanFinding(tx.QueryRow(ctx,
			`SELECT `+findingCols+` FROM findings WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO finding_status_history (finding_id, from_status, to_status, changed_by, note)
			 VALUES ($1, $2, $3, $4, $5)`, current.ID, current.Status, status, changedBy, note); err != nil {
			return fmt.Errorf("record status history: %w", err)
		}
		updated, err := scanFinding(tx.QueryRow(ctx,
			`UPDATE findings SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+findingCols, id, status))
		if err != nil {
			return err
		}
		out = &updated
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.audit != nil {
		var uid *uuid.UUID
		if changedBy != nil {
			uid = changedBy
		}
		s.audit.Log(ctx, uid, "finding.status_update", "finding", id.String(),
			map[string]any{"from": "", "to": status, "note": note}, "")
	}
	return out, nil
}

// ManualInput describes a finding an analyst registers by hand.
type ManualInput struct {
	AssetID          uuid.UUID
	Title            string
	Description      string
	TechnicalDetails string
	Evidence         string
	Severity         string
	Port             *int
	Protocol         string
	Service          string
	CVEs             []string
	CVSSScore        *float64
	Remediation      string
	References       []string
	Scanner          string
	Note             string
}

// Create registers a finding without a scan. It uses the same fingerprint rule
// as ingestion, so a manual finding and a scanner finding for the same issue on
// the same asset dedupe into one row rather than appearing twice.
func (s *Service) Create(ctx context.Context, projectID uuid.UUID, in ManualInput) (*models.Finding, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return nil, fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	severity := normalizeSeverity(in.Severity)
	scanner := strings.TrimSpace(in.Scanner)
	if scanner == "" {
		scanner = "manual"
	}
	var assetProject uuid.UUID
	if err := s.db.QueryRow(ctx, `SELECT project_id FROM assets WHERE id = $1`, in.AssetID).Scan(&assetProject); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: asset %s does not exist", ErrInvalidInput, in.AssetID)
		}
		return nil, err
	}
	if assetProject != projectID {
		return nil, fmt.Errorf("%w: asset belongs to another project", ErrInvalidInput)
	}
	refs := json.RawMessage(`[]`)
	if len(in.References) > 0 {
		b, err := json.Marshal(in.References)
		if err != nil {
			return nil, err
		}
		refs = b
	}
	cves := in.CVEs
	if cves == nil {
		cves = []string{}
	}
	fp := FindingFingerprint(title, scanner, in.Port, in.Protocol)

	var finding models.Finding
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		created, err := scanFinding(tx.QueryRow(ctx,
			`INSERT INTO findings
			 (project_id, asset_id, title, description, technical_details, evidence, scanner,
			  port, protocol, service, cves, cvss_score, severity, status, remediation, "references",
			  fingerprint, first_detected, last_detected, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'open',$14,$15,$16,now(),now(),now(),now())
			 ON CONFLICT (project_id, asset_id, fingerprint) DO NOTHING
			 RETURNING `+findingCols,
			projectID, in.AssetID, title, in.Description, in.TechnicalDetails, in.Evidence, scanner,
			in.Port, nullableText(in.Protocol), nullableText(in.Service), cves, in.CVSSScore,
			severity, in.Remediation, refs, fp))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
		finding = created
		note := strings.TrimSpace(in.Note)
		if note == "" {
			note = "registered manually"
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO finding_status_history (finding_id, from_status, to_status, changed_by, note)
			 VALUES ($1, '', $2, $3, $4)`, finding.ID, models.FindingStatusOpen, nil, note)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &finding, nil
}

// ───────────────────────────────────────────── HTTP

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q := r.URL.Query()
	filters := Filters{
		Severity: q.Get("severity"),
		Status:   q.Get("status"),
		Scanner:  q.Get("scanner"),
		Query:    q.Get("q"),
		Sort:     q.Get("sort"),
		Desc:     !strings.EqualFold(q.Get("order"), "asc"),
		Limit:    intQuery(r, "limit", 100),
		Offset:   intQuery(r, "offset", 0),
	}
	if raw := q.Get("asset_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			api.WriteError(w, http.StatusBadRequest, "invalid asset_id")
			return
		}
		filters.AssetID = &parsed
	}
	items, total, err := s.List(r.Context(), projectID, filters)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteList(w, items, total)
}

type createFindingRequest struct {
	AssetID          uuid.UUID `json:"asset_id"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	TechnicalDetails string    `json:"technical_details"`
	Evidence         string    `json:"evidence"`
	Severity         string    `json:"severity"`
	Port             *int      `json:"port"`
	Protocol         string    `json:"protocol"`
	Service          string    `json:"service"`
	CVEs             []string  `json:"cves"`
	CVSSScore        *float64  `json:"cvss_score"`
	Remediation      string    `json:"remediation"`
	References       []string  `json:"references"`
	Scanner          string    `json:"scanner"`
	Note             string    `json:"note"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	projectID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body createFindingRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	finding, err := s.Create(r.Context(), projectID, ManualInput{
		AssetID: body.AssetID, Title: body.Title, Description: body.Description,
		TechnicalDetails: body.TechnicalDetails, Evidence: body.Evidence, Severity: body.Severity,
		Port: body.Port, Protocol: body.Protocol, Service: body.Service, CVEs: body.CVEs,
		CVSSScore: body.CVSSScore, Remediation: body.Remediation, References: body.References,
		Scanner: body.Scanner, Note: body.Note,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	user := api.UserFromContext(r.Context())
	if s.audit != nil {
		var uid *uuid.UUID
		if user != nil {
			uid = &user.ID
		}
		s.audit.LogRequest(r, uid, "finding.create", "finding", finding.ID.String(),
			map[string]any{"title": finding.Title, "asset_id": body.AssetID.String()})
	}
	api.WriteJSON(w, http.StatusCreated, finding)
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	finding, err := s.Get(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	// VER-002: stated project scope must own the resource.
	if !api.ProjectScopeMatches(r, finding.ProjectID) {
		api.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	api.WriteJSON(w, http.StatusOK, finding)
}

type statusRequest struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body statusRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	user := api.UserFromContext(r.Context())
	var uid *uuid.UUID
	if user != nil {
		uid = &user.ID
	}
	if existing, err := s.Get(r.Context(), id); err == nil &&
		!api.ProjectScopeMatches(r, existing.ProjectID) {
		api.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	finding, err := s.UpdateStatus(r.Context(), id, body.Status, body.Note, uid)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, finding)
}

func (s *Service) handleHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if existing, err := s.Get(r.Context(), id); err == nil &&
		!api.ProjectScopeMatches(r, existing.ProjectID) {
		api.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	history, err := s.History(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, history)
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		api.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		api.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrEmptyResult):
		api.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrExecutionMismatch):
		api.WriteError(w, http.StatusNotFound, err.Error())
	default:
		api.WriteError(w, http.StatusInternalServerError, "finding operation failed")
	}
}

func scanFinding(row pgx.Row) (models.Finding, error) {
	var f models.Finding
	err := row.Scan(&f.ID, &f.ProjectID, &f.AssetID, &f.Title, &f.Description, &f.TechnicalDetails,
		&f.Evidence, &f.Scanner, &f.Port, &f.Protocol, &f.Service, &f.CVEs, &f.CVSSScore,
		&f.Severity, &f.Status, &f.Remediation, &f.References, &f.Fingerprint,
		&f.FirstDetected, &f.LastDetected, &f.CreatedAt, &f.UpdatedAt)
	if f.CVEs == nil {
		f.CVEs = []string{}
	}
	if len(f.References) == 0 {
		f.References = json.RawMessage(`[]`)
	}
	return f, err
}

func findingSort(field string, desc bool) (string, bool) {
	if field == "" {
		field = "last_detected"
	}
	col, ok := map[string]string{
		"last_detected":  "last_detected",
		"first_detected": "first_detected",
		"created_at":     "created_at",
		"updated_at":     "updated_at",
		"title":          "lower(title)",
		"severity":       "severity",
		"status":         "status",
		"scanner":        "scanner",
		"cvss_score":     "cvss_score",
	}[field]
	if !ok {
		return "", false
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	// Severity sorts by business impact, not alphabetically, and the ranking is
	// oriented so that the default (descending) lists critical findings first.
	if col == "severity" {
		return `CASE severity
			WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
			WHEN 'low' THEN 1 ELSE 0 END ` + dir + `, id ASC`, true
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
