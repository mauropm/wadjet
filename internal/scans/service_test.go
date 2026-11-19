package scans

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
	"github.com/mauropm/wadjet/internal/models"
)

const testDatabaseURL = "postgres://wadjet:wadjet@127.0.0.1:5432/wadjet"

func openTestDB(t *testing.T) *database.DB {
	t.Helper()
	var (
		db  *database.DB
		err error
	)
	deadline := time.Now().Add(30 * time.Second)
	for {
		db, err = database.Open(context.Background(), testDatabaseURL)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("test database unavailable: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Cleanup(db.Close)
	require.NoError(t, database.Migrate(context.Background(), db))
	return db
}

// ── fakes ───────────────────────────────────────────────────────────────

type fakeRegistry struct {
	mu        sync.Mutex
	enabled   map[string]bool
	records   map[string]models.ScannerRecord
	disabledN int
	enabledN  int
}

func newFakeRegistry(names ...string) *fakeRegistry {
	r := &fakeRegistry{enabled: map[string]bool{}, records: map[string]models.ScannerRecord{}}
	for _, n := range names {
		r.enabled[n] = true
		r.records[n] = models.ScannerRecord{ID: uuid.New(), Name: n, DisplayName: n, Adapter: "command", Enabled: true, Status: "available"}
	}
	return r
}

func (r *fakeRegistry) List(ctx context.Context) ([]models.ScannerRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []models.ScannerRecord
	for _, rec := range r.records {
		out = append(out, rec)
	}
	return out, nil
}

func (r *fakeRegistry) GetRecord(ctx context.Context, idOrName string) (models.ScannerRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.records[idOrName]; ok {
		return rec, nil
	}
	return models.ScannerRecord{}, errors.New("not found")
}

func (r *fakeRegistry) Enable(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled[name] = true
	r.enabledN++
	rec := r.records[name]
	rec.Enabled = true
	r.records[name] = rec
	return nil
}

func (r *fakeRegistry) Disable(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled[name] = false
	r.disabledN++
	rec := r.records[name]
	rec.Enabled = false
	r.records[name] = rec
	return nil
}

func (r *fakeRegistry) CheckAvailability(ctx context.Context, name string) (models.ScannerRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.records[name]; ok {
		rec.Status = "available"
		return rec, nil
	}
	return models.ScannerRecord{}, errors.New("not found")
}

func (r *fakeRegistry) Enabled(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled[name]
}

type fakeOrchestrator struct {
	mu        sync.Mutex
	started   []uuid.UUID
	startErr  error
	cancelRet bool
	cancelled []uuid.UUID
}

func (o *fakeOrchestrator) StartSession(ctx context.Context, id uuid.UUID) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.startErr != nil {
		return o.startErr
	}
	o.started = append(o.started, id)
	return nil
}

func (o *fakeOrchestrator) Cancel(id uuid.UUID) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cancelled = append(o.cancelled, id)
	return o.cancelRet
}

// ── helpers ─────────────────────────────────────────────────────────────

func newTestService(t *testing.T) (*Service, *database.DB, *fakeRegistry, *fakeOrchestrator, *events.Bus) {
	t.Helper()
	db := openTestDB(t)
	reg := newFakeRegistry("alpha", "beta")
	orch := &fakeOrchestrator{cancelRet: false}
	bus := events.New()
	svc := NewService(db, reg, orch, bus)
	return svc, db, reg, orch, bus
}

func mount(svc *Service) *httptest.Server {
	r := chi.NewRouter()
	svc.Register(r)
	s := httptest.NewServer(r)
	return s
}

func doJSON(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func decodeError(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	// Keep the body replayable for subsequent decodes in happy paths.
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return "<unreadable body>"
	}
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Error.Message == "" {
		return string(body)
	}
	return e.Error.Message
}

func mkProjectRow(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, db.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ($1) RETURNING id`,
		"scans-test-"+uuid.New().String()).Scan(&id))
	return id
}

func sessionStatus(t *testing.T, db *database.DB, id uuid.UUID) string {
	t.Helper()
	var s string
	require.NoError(t, db.QueryRow(context.Background(),
		`SELECT status FROM scan_sessions WHERE id=$1`, id).Scan(&s))
	return s
}

// ── tests ───────────────────────────────────────────────────────────────

func TestCreateScanAdHoc(t *testing.T) {
	svc, db, _, _, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"name":    "nightly",
		"targets": []string{"10.0.0.0/28", "127.0.0.1"},
		"scanner_configs": []map[string]any{
			{"scanner": "alpha", "config": map[string]any{"timing": "fast"}},
			{"scanner": "beta"},
		},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, decodeError(t, resp))
	var created struct {
		ID      uuid.UUID `json:"id"`
		Status  string    `json:"status"`
		Targets []string  `json:"targets"`
		Execs   []struct {
			ScannerName string          `json:"scanner_name"`
			Status      string          `json:"status"`
			Config      json.RawMessage `json:"config"`
		} `json:"executions"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	assert.Equal(t, models.ScanStatusDraft, created.Status)
	assert.Len(t, created.Targets, 2)
	require.Len(t, created.Execs, 2)
	assert.Equal(t, models.ExecStatusQueued, created.Execs[0].Status)
	assert.Contains(t, string(created.Execs[0].Config), "fast")

	// session targets persisted
	var n int
	require.NoError(t, db.QueryRow(context.Background(),
		`SELECT count(*) FROM scan_session_targets WHERE session_id=$1`, created.ID).Scan(&n))
	assert.Equal(t, 2, n)
}

func TestCreateScanValidation(t *testing.T) {
	svc, db, _, _, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()
	base := srv.URL + "/projects/"

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{"bad project uuid", http.MethodPost, "not-a-uuid/scans", map[string]any{}, http.StatusBadRequest},
		{"unknown project", http.MethodPost, projectID.String() + "f/scans", map[string]any{}, http.StatusBadRequest},
		{"no targets", http.MethodPost, projectID.String() + "/scans", map[string]any{"scanner_configs": []any{map[string]any{"scanner": "alpha"}}}, http.StatusBadRequest},
		{"both sources", http.MethodPost, projectID.String() + "/scans", map[string]any{"targets": []string{"a"}, "scanner_configs": []any{map[string]any{"scanner": "alpha"}}, "profile_id": uuid.New()}, http.StatusBadRequest},
		{"neither source", http.MethodPost, projectID.String() + "/scans", map[string]any{"targets": []string{"a"}}, http.StatusBadRequest},
		{"duplicate scanner", http.MethodPost, projectID.String() + "/scans", map[string]any{"targets": []string{"a"}, "scanner_configs": []any{map[string]any{"scanner": "alpha"}, map[string]any{"scanner": "alpha"}}}, http.StatusBadRequest},
		{"unknown scanner", http.MethodPost, projectID.String() + "/scans", map[string]any{"targets": []string{"a"}, "scanner_configs": []any{map[string]any{"scanner": "ghost"}}}, http.StatusUnprocessableEntity},
		{"missing body", http.MethodPost, projectID.String() + "/scans", nil, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, tc.method, base+tc.path, tc.body)
			msg := decodeError(t, resp)
			assert.Equal(t, tc.want, resp.StatusCode, msg)
		})
	}

	t.Run("project not found", func(t *testing.T) {
		resp := doJSON(t, http.MethodPost, base+uuid.New().String()+"/scans", map[string]any{
			"targets":         []string{"10.0.0.1"},
			"scanner_configs": []any{map[string]any{"scanner": "alpha"}},
		})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestCreateScanFromProfile(t *testing.T) {
	svc, db, _, _, _ := newTestService(t)
	ctx := context.Background()
	projectID := mkProjectRow(t, db)

	// Persist scanner rows so profile bindings can join by name.
	for _, n := range []string{"alpha", "beta"} {
		_, err := db.Exec(ctx, `
			INSERT INTO scanners (name, display_name, adapter) VALUES ($1,$1,'command')
			ON CONFLICT (name) DO NOTHING`, n)
		require.NoError(t, err)
	}
	var profileID uuid.UUID
	require.NoError(t, db.QueryRow(ctx, `
		INSERT INTO scan_profiles (project_id, name, target_selection, excluded_targets)
		VALUES ($1,'std',$2,$3) RETURNING id`,
		projectID,
		[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		[]string{"10.0.0.2"}).Scan(&profileID))
	var alphaID, betaID uuid.UUID
	require.NoError(t, db.QueryRow(ctx, `SELECT id FROM scanners WHERE name='alpha'`).Scan(&alphaID))
	require.NoError(t, db.QueryRow(ctx, `SELECT id FROM scanners WHERE name='beta'`).Scan(&betaID))
	_, err := db.Exec(ctx, `INSERT INTO scan_profile_scanners (profile_id, scanner_id, config, sort_order) VALUES ($1,$2,'{"x":1}',0)`, profileID, alphaID)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO scan_profile_scanners (profile_id, scanner_id, config, sort_order) VALUES ($1,$2,'{}',1)`, profileID, betaID)
	require.NoError(t, err)

	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"profile_id": profileID,
		"targets":    []string{"placeholder"},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, decodeError(t, resp))
	var created struct {
		ID           uuid.UUID  `json:"id"`
		ProfileID    *uuid.UUID `json:"profile_id"`
		Targets      []string   `json:"targets"`
		ScannerNames []string   `json:"scanner_names"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	require.NotNil(t, created.ProfileID)
	assert.Equal(t, uuid.MustParse(profileID.String()), *created.ProfileID)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.3"}, created.Targets, "excluded target removed")
	assert.ElementsMatch(t, []string{"alpha", "beta"}, created.ScannerNames)
}

func TestGetScanDetailAndList(t *testing.T) {
	svc, db, _, _, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"name":            "detail-me",
		"targets":         []string{"127.0.0.1"},
		"scanner_configs": []any{map[string]any{"scanner": "alpha"}},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, decodeError(t, resp))
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	// detail
	resp = doJSON(t, http.MethodGet, srv.URL+"/scans/"+created.ID.String(), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var detail struct {
		ID             uuid.UUID `json:"id"`
		Executions     []any     `json:"executions"`
		SessionTargets []struct {
			Target string `json:"target"`
			Status string `json:"status"`
		} `json:"session_targets"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&detail))
	resp.Body.Close()
	assert.Len(t, detail.Executions, 1)
	require.Len(t, detail.SessionTargets, 1)
	assert.Equal(t, "127.0.0.1", detail.SessionTargets[0].Target)
	assert.Equal(t, "pending", detail.SessionTargets[0].Status)

	// list
	resp = doJSON(t, http.MethodGet, srv.URL+"/projects/"+projectID.String()+"/scans", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list struct {
		Items []struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	resp.Body.Close()
	assert.Equal(t, 1, list.Total)
	require.Len(t, list.Items, 1)
	assert.Equal(t, "detail-me", list.Items[0].Name)

	// 404s
	resp = doJSON(t, http.MethodGet, srv.URL+"/scans/"+uuid.New().String(), nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
	resp = doJSON(t, http.MethodGet, srv.URL+"/scans/nope", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestStartScanLifecycle(t *testing.T) {
	svc, db, _, orch, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"targets":         []string{"127.0.0.1"},
		"scanner_configs": []any{map[string]any{"scanner": "alpha"}},
	})
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	// start from draft
	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+created.ID.String()+"/start", nil)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, decodeError(t, resp))
	resp.Body.Close()
	// The service queues; the orchestrator (real one) flips queued→running.
	// The fake only records the call, so emulate the orchestrator's flip.
	assert.Equal(t, models.ScanStatusQueued, sessionStatus(t, db, created.ID))
	_, err := db.Exec(context.Background(),
		`UPDATE scan_sessions SET status='running' WHERE id=$1`, created.ID)
	require.NoError(t, err)
	orch.mu.Lock()
	assert.Equal(t, []uuid.UUID{created.ID}, orch.started)
	orch.mu.Unlock()

	// start again while running → 409
	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+created.ID.String()+"/start", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()

	// start unknown → 404
	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+uuid.New().String()+"/start", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestStartScanOrchestratorFailureRollsBack(t *testing.T) {
	svc, db, _, orch, _ := newTestService(t)
	orch.startErr = errors.New("session is not queued")
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"targets":         []string{"127.0.0.1"},
		"scanner_configs": []any{map[string]any{"scanner": "alpha"}},
	})
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+created.ID.String()+"/start", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
	assert.Equal(t, models.ScanStatusQueued, sessionStatus(t, db, created.ID),
		"failed start must roll back to queued for retry")
}

func TestStartCancelledResetsExecutions(t *testing.T) {
	svc, db, _, orch, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"targets":         []string{"127.0.0.1"},
		"scanner_configs": []any{map[string]any{"scanner": "alpha"}, map[string]any{"scanner": "beta"}},
	})
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	// force into cancelled with one completed + one failed execution
	_, err := db.Exec(context.Background(), `UPDATE scan_sessions SET status='cancelled' WHERE id=$1`, created.ID)
	require.NoError(t, err)
	_, err = db.Exec(context.Background(), `UPDATE scanner_executions SET status='completed' WHERE session_id=$1 AND scanner_name='alpha'`, created.ID)
	require.NoError(t, err)
	_, err = db.Exec(context.Background(), `UPDATE scanner_executions SET status='failed' WHERE session_id=$1 AND scanner_name='beta'`, created.ID)
	require.NoError(t, err)

	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+created.ID.String()+"/start", nil)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, decodeError(t, resp))
	resp.Body.Close()

	rows, err := db.Query(context.Background(),
		`SELECT scanner_name, status FROM scanner_executions WHERE session_id=$1 ORDER BY scanner_name`, created.ID)
	require.NoError(t, err)
	defer rows.Close()
	statuses := map[string]string{}
	for rows.Next() {
		var n, s string
		require.NoError(t, rows.Scan(&n, &s))
		statuses[n] = s
	}
	assert.Equal(t, "completed", statuses["alpha"], "completed work is kept")
	assert.Equal(t, "queued", statuses["beta"], "failed work is retried")
	orch.mu.Lock()
	assert.Len(t, orch.started, 1)
	orch.mu.Unlock()
}

func TestCancelScan(t *testing.T) {
	svc, db, _, orch, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	// queued session: direct cancel
	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"targets":         []string{"127.0.0.1"},
		"scanner_configs": []any{map[string]any{"scanner": "alpha"}},
	})
	var queued struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&queued))
	resp.Body.Close()

	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+queued.ID.String()+"/cancel", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.Equal(t, models.ScanStatusCancelled, sessionStatus(t, db, queued.ID))

	// running session not in this process (Cancel=false): force-cancel path
	var running uuid.UUID
	require.NoError(t, db.QueryRow(context.Background(), `
		INSERT INTO scan_sessions (project_id, status, targets, scanner_names)
		VALUES ($1,'running','{127.0.0.1}','{alpha}') RETURNING id`, projectID).Scan(&running))
	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+running.String()+"/cancel", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.Equal(t, models.ScanStatusCancelled, sessionStatus(t, db, running))
	orch.mu.Lock()
	assert.Contains(t, orch.cancelled, running)
	orch.mu.Unlock()

	// completed → 409
	var done uuid.UUID
	require.NoError(t, db.QueryRow(context.Background(), `
		INSERT INTO scan_sessions (project_id, status) VALUES ($1,'completed') RETURNING id`, projectID).Scan(&done))
	resp = doJSON(t, http.MethodPost, srv.URL+"/scans/"+done.String()+"/cancel", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

func TestScannerEndpoints(t *testing.T) {
	svc, _, reg, _, _ := newTestService(t)
	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodGet, srv.URL+"/scanners", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list struct {
		Items []models.ScannerRecord `json:"items"`
		Total int                    `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	resp.Body.Close()
	assert.Equal(t, 2, list.Total)

	resp = doJSON(t, http.MethodGet, srv.URL+"/scanners/alpha", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	resp = doJSON(t, http.MethodGet, srv.URL+"/scanners/ghost", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()

	resp = doJSON(t, http.MethodPut, srv.URL+"/scanners/alpha/enabled", map[string]any{"enabled": false})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var rec models.ScannerRecord
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rec))
	resp.Body.Close()
	assert.False(t, rec.Enabled)
	assert.False(t, reg.Enabled("alpha"))

	resp = doJSON(t, http.MethodPut, srv.URL+"/scanners/alpha/enabled", map[string]any{"enabled": true})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	assert.True(t, reg.Enabled("alpha"))

	resp = doJSON(t, http.MethodPost, srv.URL+"/scanners/alpha/check", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestSSEStreamFiltersSession(t *testing.T) {
	svc, db, _, _, bus := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"targets":         []string{"127.0.0.1"},
		"scanner_configs": []any{map[string]any{"scanner": "alpha"}},
	})
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()

	reqCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		srv.URL+"/scans/"+created.ID.String()+"/events", nil)
	require.NoError(t, err)

	// Publish one matching and one foreign event after the subscriber attaches.
	go func() {
		time.Sleep(150 * time.Millisecond)
		bus.Publish(events.Event{Topic: "scan", Kind: "execution.status",
			Payload: map[string]any{"session_id": created.ID.String(), "status": "running"}})
		bus.Publish(events.Event{Topic: "scan", Kind: "scan.status",
			Payload: map[string]any{"session_id": uuid.New().String(), "status": "running"}})
		time.Sleep(150 * time.Millisecond)
		cancel() // end the stream
	}()

	respSSE, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer respSSE.Body.Close()
	assert.Equal(t, "text/event-stream", respSSE.Header.Get("Content-Type"))

	buf := &bytes.Buffer{}
	_, _ = buf.ReadFrom(respSSE.Body)
	body := buf.String()
	assert.Contains(t, body, "event: scan")
	assert.Contains(t, body, created.ID.String())
	assert.NotContains(t, body, "no-such")
}

func TestDecodeBodyLimit(t *testing.T) {
	svc, db, _, _, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	srv := mount(svc)
	defer srv.Close()

	huge := make([]string, 60000)
	for i := range huge {
		huge[i] = "10.0.0.1"
	}
	resp, err := http.Post(srv.URL+"/projects/"+projectID.String()+"/scans",
		"application/json", bytes.NewReader(mustMarshal(t, map[string]any{"targets": huge, "scanner_configs": []any{map[string]any{"scanner": "alpha"}}})))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "oversized bodies are rejected")
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestProfileBindingsWrongProject(t *testing.T) {
	svc, db, _, _, _ := newTestService(t)
	projectID := mkProjectRow(t, db)
	other := mkProjectRow(t, db)
	var profileID uuid.UUID
	require.NoError(t, db.QueryRow(context.Background(),
		`INSERT INTO scan_profiles (project_id, name) VALUES ($1,'p') RETURNING id`, other).Scan(&profileID))

	srv := mount(svc)
	defer srv.Close()
	resp := doJSON(t, http.MethodPost, srv.URL+"/projects/"+projectID.String()+"/scans", map[string]any{
		"targets":    []string{"10.0.0.1"},
		"profile_id": profileID,
	})
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	msg := decodeError(t, resp)
	assert.Contains(t, msg, "profile")
	_ = fmt.Sprint()
}
