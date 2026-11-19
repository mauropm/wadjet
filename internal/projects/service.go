// Package projects implements the project domain: the top-level assessment
// scope that owns targets, assets, findings, profiles and scans.
//
// Ownership: Agent 3.
//
// Retention policy (documented, enforced in Delete):
//
//   - A project can only be deleted once it is archived. An active project
//     always returns HTTP 409.
//   - An archived project is *retained*: it is only physically removed when
//     the caller also passes ?force=true. Without force the API returns 409
//     so that accidental deletes keep the assessment history (sessions,
//     findings, observations) recoverable.
//
// Every mutation is written to the audit log via internal/audit.
package projects

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/audit"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

// Sentinel errors for the project domain.
var (
	// ErrNotFound is returned when no project row matches the requested id.
	ErrNotFound = errors.New("project not found")
	// ErrNotArchived is returned by Delete for an active project.
	ErrNotArchived = errors.New("project must be archived before it can be deleted")
	// ErrRetentionPolicy is returned by Delete for an archived project when
	// force=true was not supplied.
	ErrRetentionPolicy = errors.New("archived project is retained; repeat the request with force=true to delete it")
	// ErrInvalidInput is returned for malformed input.
	ErrInvalidInput = errors.New("invalid project input")
)

// Service provides project operations and the /projects HTTP surface.
type Service struct {
	db    *database.DB
	audit *audit.Logger
}

// NewService builds the project service. auditLogger may be nil (used by
// tests that do not assert on audit rows).
func NewService(db *database.DB, auditLogger *audit.Logger) *Service {
	return &Service{db: db, audit: auditLogger}
}

// Register mounts the project routes. r is the /api/v1 router with auth
// middleware already applied.
func (s *Service) Register(r chi.Router) {
	r.Get("/projects", s.handleList)
	r.Post("/projects", s.handleCreate)
	r.Get("/projects/{id}", s.handleGet)
	r.Put("/projects/{id}", s.handleUpdate)
	r.Delete("/projects/{id}", s.handleDelete)
	r.Post("/projects/{id}/clone", s.handleClone)
	r.Post("/projects/{id}/archive", s.handleArchive)
}

// ───────────────────────────────────────────── domain operations

// Create inserts a new active project.
func (s *Service) Create(ctx context.Context, input CreateInput) (*models.Project, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, ErrInvalidInput
	}
	if len([]rune(name)) > 200 {
		return nil, ErrInvalidInput
	}
	settings := input.Settings
	if len(settings) == 0 || string(settings) == "null" {
		settings = json.RawMessage(`{}`)
	} else if !isJSONObject(settings) {
		return nil, ErrInvalidInput
	}
	var createdBy *uuid.UUID
	if input.CreatedBy != uuid.Nil {
		createdBy = &input.CreatedBy
	}
	row := s.db.QueryRow(ctx,
		`INSERT INTO projects (name, description, status, tags, settings, created_by, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now())
		 RETURNING `+projectCols,
		name, input.Description, models.ProjectStatusActive, normalizeTags(input.Tags), settings, createdBy)
	p, err := scanProject(row)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Get loads one project by id.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*models.Project, error) {
	row := s.db.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE id = $1`, id)
	p, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// ListFilters narrows List.
type ListFilters struct {
	Query      string // ILIKE over name, description and tags
	Status     string
	Limit      int
	Offset     int
	Sort       string
	Descending bool
}

// List returns projects matching the filters plus the total match count.
func (s *Service) List(ctx context.Context, f ListFilters) ([]models.Project, int, error) {
	var conds []string
	var args []any
	// add appends one condition. Every "?" in cond is replaced by the next
	// placeholder and receives a copy of arg, so a single value can be reused
	// by several alternatives in the same condition.
	add := func(cond string, arg any) {
		base := len(args)
		n := strings.Count(cond, "?")
		for i := 0; i < n; i++ {
			cond = strings.Replace(cond, "?", "$"+strconv.Itoa(base+i+1), 1)
			args = append(args, arg)
		}
		conds = append(conds, cond)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + escapeLike(q) + "%"
		add(`(name ILIKE ? OR description ILIKE ? OR EXISTS
		      (SELECT 1 FROM unnest(tags) AS t(tag) WHERE t.tag ILIKE ?))`, like)
	}
	if f.Status != "" {
		if f.Status != models.ProjectStatusActive && f.Status != models.ProjectStatusArchived {
			return nil, 0, ErrInvalidInput
		}
		add("status = ?", f.Status)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM projects`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy, ok := projectSort(f.Sort, f.Descending)
	if !ok {
		return nil, 0, ErrInvalidInput
	}
	limit := clampInt(f.Limit, 50, 1, 500)
	offset := clampInt(f.Offset, 0, 0, 1<<31-1)

	rows, err := s.db.Query(ctx,
		`SELECT `+projectCols+` FROM projects`+where+` ORDER BY `+orderBy+` LIMIT $`+strconv.Itoa(len(args)+1)+` OFFSET $`+strconv.Itoa(len(args)+2),
		append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []models.Project{}
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// UpdateInput carries optional fields; nil means "leave unchanged".
type UpdateInput struct {
	Name        *string
	Description *string
	Status      *string
	Tags        *[]string
	Settings    json.RawMessage
}

// Update applies a partial update and bumps updated_at.
func (s *Service) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*models.Project, error) {
	var sets []string
	var args []any
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, col+" = $"+strconv.Itoa(len(args)))
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len([]rune(name)) > 200 {
			return nil, ErrInvalidInput
		}
		add("name", name)
	}
	if in.Description != nil {
		add("description", *in.Description)
	}
	if in.Status != nil {
		if *in.Status != models.ProjectStatusActive && *in.Status != models.ProjectStatusArchived {
			return nil, ErrInvalidInput
		}
		add("status", *in.Status)
	}
	if in.Tags != nil {
		add("tags", normalizeTags(*in.Tags))
	}
	if len(in.Settings) > 0 && string(in.Settings) != "null" {
		if !isJSONObject(in.Settings) {
			return nil, ErrInvalidInput
		}
		add("settings", in.Settings)
	}
	if len(sets) == 0 {
		return s.Get(ctx, id)
	}
	sets = append(sets, "updated_at = now()")
	args = append(args, id)
	row := s.db.QueryRow(ctx,
		`UPDATE projects SET `+strings.Join(sets, ", ")+` WHERE id = $`+strconv.Itoa(len(args))+
			` RETURNING `+projectCols, args...)
	p, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// Archive marks a project archived. It is idempotent.
func (s *Service) Archive(ctx context.Context, id uuid.UUID) (*models.Project, error) {
	row := s.db.QueryRow(ctx,
		`UPDATE projects SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+projectCols,
		id, models.ProjectStatusArchived)
	p, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// Delete removes a project (cascading to all child rows) but only under the
// retention policy described in the package documentation.
//
// Retention rules:
//
//   - active project                        -> ErrNotArchived   (HTTP 409)
//   - archived project, force == false      -> ErrRetentionPolicy (HTTP 409)
//   - archived project, force == true       -> deleted
func (s *Service) Delete(ctx context.Context, id uuid.UUID, force bool) error {
	p, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if p.Status != models.ProjectStatusArchived {
		return ErrNotArchived
	}
	if !force {
		return ErrRetentionPolicy
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchActivity stamps last_activity_at with the current time. The scan
// orchestrator and the ingestion pipeline call it whenever a scan or an
// ingest touches the project.
func (s *Service) TouchActivity(ctx context.Context, projectID uuid.UUID) error {
	_, err := s.db.Exec(ctx, `UPDATE projects SET last_activity_at = now() WHERE id = $1`, projectID)
	return err
}

// ───────────────────────────────────────────── HTTP handlers

// CreateInput is the service-level create payload.
type CreateInput struct {
	Name        string
	Description string
	Tags        []string
	Settings    json.RawMessage
	CreatedBy   uuid.UUID
}

type createRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Tags        []string        `json:"tags"`
	Settings    json.RawMessage `json:"settings"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	var body createRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	user := api.UserFromContext(r.Context())
	in := CreateInput{Name: body.Name, Description: body.Description, Tags: body.Tags, Settings: body.Settings}
	if user != nil {
		in.CreatedBy = user.ID
	}
	p, err := s.Create(r.Context(), in)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	s.log(r, user, "project.create", p, map[string]any{"name": p.Name})
	api.WriteJSON(w, http.StatusCreated, p)
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sortField := q.Get("sort")
	if sortField == "" {
		sortField = "created_at"
	}
	descending := true
	if o := strings.ToLower(q.Get("order")); o == "asc" {
		descending = false
	}
	f := ListFilters{
		Query:      q.Get("q"),
		Status:     q.Get("status"),
		Limit:      intQuery(r, "limit", 50),
		Offset:     intQuery(r, "offset", 0),
		Sort:       sortField,
		Descending: descending,
	}
	items, total, err := s.List(r.Context(), f)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	api.WriteList(w, items, total)
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	p, err := s.Get(r.Context(), id)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, p)
}

type updateRequest struct {
	Name        *string         `json:"name"`
	Description *string         `json:"description"`
	Status      *string         `json:"status"`
	Tags        *[]string       `json:"tags"`
	Settings    json.RawMessage `json:"settings"`
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	var body updateRequest
	if err := api.DecodeJSON(r, &body); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	before, err := s.Get(r.Context(), id)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	p, err := s.Update(r.Context(), id, UpdateInput{
		Name:        body.Name,
		Description: body.Description,
		Status:      body.Status,
		Tags:        body.Tags,
		Settings:    body.Settings,
	})
	if err != nil {
		writeProjectError(w, err)
		return
	}
	user := api.UserFromContext(r.Context())
	s.log(r, user, "project.update", p, map[string]any{"from_name": before.Name, "from_status": before.Status})
	api.WriteJSON(w, http.StatusOK, p)
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	force := strings.EqualFold(r.URL.Query().Get("force"), "true")
	if err := s.Delete(r.Context(), id, force); err != nil {
		writeProjectError(w, err)
		return
	}
	user := api.UserFromContext(r.Context())
	s.log(r, user, "project.delete", &models.Project{ID: id}, map[string]any{"force": force})
	api.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Service) handleArchive(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r)
	if !ok {
		return
	}
	p, err := s.Archive(r.Context(), id)
	if err != nil {
		writeProjectError(w, err)
		return
	}
	user := api.UserFromContext(r.Context())
	s.log(r, user, "project.archive", p, nil)
	api.WriteJSON(w, http.StatusOK, p)
}

// log never fails the request: audit.Logger swallows its own errors.
func (s *Service) log(r *http.Request, user *models.User, action string, p *models.Project, details any) {
	if s.audit == nil {
		return
	}
	var uid *uuid.UUID
	if user != nil {
		uid = &user.ID
	}
	s.audit.LogRequest(r, uid, action, "project", p.ID.String(), details)
}

func writeProjectError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		api.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrNotArchived), errors.Is(err, ErrRetentionPolicy):
		api.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrInvalidInput):
		api.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		api.WriteError(w, http.StatusInternalServerError, "project operation failed")
	}
}

// ───────────────────────────────────────────── shared helpers

const projectCols = `id, name, description, status, tags, settings, created_by, created_at, updated_at, last_activity_at`

func scanProject(row pgx.Row) (models.Project, error) {
	var p models.Project
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Status, &p.Tags, &p.Settings,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.LastActivity)
	if p.Tags == nil {
		p.Tags = []string{}
	}
	if len(p.Settings) == 0 {
		p.Settings = json.RawMessage(`{}`)
	}
	return p, err
}

// projectSort maps a whitelisted sort key to an ORDER BY clause. An empty key
// sorts by creation time; unknown keys are rejected so user input can never
// reach the query as raw SQL.
func projectSort(field string, desc bool) (string, bool) {
	if field == "" {
		field = "created_at"
	}
	col, ok := map[string]string{
		"created_at":       "created_at",
		"updated_at":       "updated_at",
		"last_activity_at": "last_activity_at",
		"name":             "lower(name)",
		"status":           "status",
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

// normalizeTags trims, drops blanks and de-duplicates while preserving order.
func normalizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		k := strings.ToLower(t)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, t)
		if len(out) >= 64 {
			break
		}
	}
	return out
}

func isJSONObject(raw json.RawMessage) bool {
	var v map[string]any
	return json.Unmarshal(raw, &v) == nil
}

// escapeLike neutralises LIKE/ILIKE wildcards in user supplied search text.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
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

func pathUUID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}
