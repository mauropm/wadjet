package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

const testDatabaseURL = "postgres://wadjet:wadjet@127.0.0.1:5432/wadjet"

func openTestDB(t *testing.T) *database.DB {
	t.Helper()
	var (
		db  *database.DB
		err error
	)
	// The shared test database may be re-provisioned concurrently by other
	// agents; retry briefly instead of failing on transient auth blips.
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

func mkProject(t *testing.T, db *database.DB) uuid.UUID {
	var id uuid.UUID
	require.NoError(t, db.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ($1) RETURNING id`,
		"agent2-test-"+uuid.New().String()).Scan(&id))
	return id
}

func mkSession(t *testing.T, db *database.DB, projectID uuid.UUID, status string, targets, scannersList []string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t, db.QueryRow(context.Background(), `
		INSERT INTO scan_sessions (project_id, name, status, targets, scanner_names)
		VALUES ($1,'test',$2,$3,$4) RETURNING id`,
		projectID, status, targets, scannersList).Scan(&id))
	for _, tg := range targets {
		_, err := db.Exec(context.Background(),
			`INSERT INTO scan_session_targets (session_id, target, status) VALUES ($1,$2,'pending')`, id, tg)
		require.NoError(t, err)
	}
	return id
}

// ── fakes ───────────────────────────────────────────────────────────────

type fakeScanner struct {
	name     string
	delay    time.Duration
	failWith error
	got      func(scanners.ScanRequest)
	result   *scanners.ScanResult
}

func (f *fakeScanner) Name() string        { return f.name }
func (f *fakeScanner) Version() string     { return "fake-1.0" }
func (f *fakeScanner) Description() string { return "test double" }
func (f *fakeScanner) Capabilities() []scanners.Capability {
	return []scanners.Capability{scanners.CapPortDiscovery}
}
func (f *fakeScanner) ValidateConfig(scanners.ScannerConfig) error { return nil }
func (f *fakeScanner) ValidateTarget(scanners.Target) error        { return nil }
func (f *fakeScanner) Execute(ctx context.Context, req scanners.ScanRequest) (*scanners.ScanResult, error) {
	if f.got != nil {
		f.got(req)
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.failWith != nil {
		return nil, f.failWith
	}
	res := f.result
	if res == nil {
		res = &scanners.ScanResult{}
	}
	if res.RawOutput == nil {
		res.RawOutput = []byte("<fake/>")
	}
	return res, nil
}

type fakeRegistry struct {
	mu       sync.Mutex
	scanners map[string]scanners.Scanner
	mfs      map[string]*manifest.Manifest
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{scanners: map[string]scanners.Scanner{}, mfs: map[string]*manifest.Manifest{}}
}

func (r *fakeRegistry) add(name string, sc scanners.Scanner, timeoutSec int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[name] = sc
	r.mfs[name] = &manifest.Manifest{Name: name, Adapter: "command", Executable: "fake"}
	if timeoutSec > 0 {
		r.mfs[name].Configuration.Timeout = timeoutSec
	}
}

func (r *fakeRegistry) Get(name string) (scanners.Scanner, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.scanners[name]
	return s, ok
}

func (r *fakeRegistry) Manifest(name string) (*manifest.Manifest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.mfs[name]
	return m, ok
}

type recordingSink struct {
	mu    sync.Mutex
	calls []sinkCall
	err   error
}

type sinkCall struct {
	SessionID, ExecutionID uuid.UUID
	Scanner                string
	Result                 *scanners.ScanResult
}

func (s *recordingSink) Ingest(ctx context.Context, sessionID, executionID uuid.UUID, scannerName string, result *scanners.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.calls = append(s.calls, sinkCall{sessionID, executionID, scannerName, result})
	return nil
}

func (s *recordingSink) Calls() []sinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sinkCall{}, s.calls...)
}

type allowlistAuthorizer struct{ denied map[string]string }

func (a allowlistAuthorizer) Authorize(ctx context.Context, projectID uuid.UUID, target string) error {
	if msg, bad := a.denied[target]; bad {
		return errors.New(msg)
	}
	return nil
}

func collectBusEvents(t *testing.T, bus *events.Bus, until func() bool) func() []events.Event {
	ch, cancel := bus.Subscribe()
	var mu sync.Mutex
	var got []events.Event
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range ch {
			mu.Lock()
			got = append(got, ev)
			mu.Unlock()
			if until != nil && until() {
				return
			}
		}
	}()
	return func() []events.Event {
		cancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		return append([]events.Event{}, got...)
	}
}

// ── tests ───────────────────────────────────────────────────────────────

func newTestOrchestrator(t *testing.T, db *database.DB, reg ScannerRegistry, sink scanners.ResultSink, authz TargetAuthorizer) (*Orchestrator, *events.Bus) {
	t.Helper()
	bus := events.New()
	rawDir := t.TempDir()
	workDir := t.TempDir()
	orch := New(db, reg, sink, bus, authz, Options{
		Concurrency: 2, DefaultTimeout: 30 * time.Second,
		RawOutputDir: rawDir, WorkDir: workDir,
	})
	return orch, bus
}

func readSession(t *testing.T, db *database.DB, id uuid.UUID) models.ScanSession {
	t.Helper()
	var sm models.ScanSession
	require.NoError(t, db.QueryRow(context.Background(),
		`SELECT id, status, error, assets_processed, findings_created FROM scan_sessions WHERE id=$1`, id).
		Scan(&sm.ID, &sm.Status, &sm.Error, &sm.AssetsProcessed, &sm.FindingsCreated))
	return sm
}

func readExecutions(t *testing.T, db *database.DB, sessionID uuid.UUID) []models.ScannerExecution {
	t.Helper()
	rows, err := db.Query(context.Background(), `
		SELECT id, scanner_name, status, raw_output_path, raw_output_bytes, assets_observed, findings_found, error, log
		FROM scanner_executions WHERE session_id=$1 ORDER BY scanner_name`, sessionID)
	require.NoError(t, err)
	defer rows.Close()
	var out []models.ScannerExecution
	for rows.Next() {
		var ex models.ScannerExecution
		require.NoError(t, rows.Scan(&ex.ID, &ex.ScannerName, &ex.Status, &ex.RawOutputPath,
			&ex.RawOutputBytes, &ex.AssetsObserved, &ex.FindingsFound, &ex.Error, &ex.Log))
		out = append(out, ex)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestOrchestratorHappyPath(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	projectID := mkProject(t, db)

	reg := newFakeRegistry()
	var mu sync.Mutex
	var seenReqs []scanners.ScanRequest
	reg.add("alpha", &fakeScanner{
		name: "alpha",
		got:  func(r scanners.ScanRequest) { mu.Lock(); seenReqs = append(seenReqs, r); mu.Unlock() },
		result: &scanners.ScanResult{
			Assets:   []scanners.AssetObservationData{{Identity: "127.0.0.1"}, {Identity: "10.9.9.9"}},
			Findings: []scanners.FindingResult{{Title: "T", Identity: "127.0.0.1", Severity: "high"}},
			Errors:   []scanners.ScannerError{{Target: "10.9.9.8", Error: "host down"}},
		},
	}, 30)
	sink := &recordingSink{}
	orch, bus := newTestOrchestrator(t, db, reg, sink, nil)

	stop := collectBusEvents(t, bus, nil)
	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1", "10.9.9.0/29"}, []string{"alpha"})
	require.NoError(t, orch.StartSession(ctx, sessionID))
	orch.Wait()

	sm := readSession(t, db, sessionID)
	assert.Equal(t, models.ScanStatusCompleted, sm.Status)
	assert.Equal(t, 2, sm.AssetsProcessed)
	assert.Equal(t, 1, sm.FindingsCreated)

	execs := readExecutions(t, db, sessionID)
	require.Len(t, execs, 1)
	ex := execs[0]
	assert.Equal(t, models.ExecStatusCompleted, ex.Status)
	assert.Equal(t, 2, ex.AssetsObserved)
	assert.Equal(t, 1, ex.FindingsFound)
	assert.NotEmpty(t, ex.RawOutputPath)
	assert.Contains(t, ex.RawOutputPath, sessionID.String())
	data, err := os.ReadFile(ex.RawOutputPath)
	require.NoError(t, err, "raw output must exist on disk")
	assert.Equal(t, "<fake/>", string(data))
	assert.Equal(t, int64(len(data)), ex.RawOutputBytes)
	assert.Contains(t, ex.Log, "host down", "per-target errors recorded in execution log")

	calls := sink.Calls()
	require.Len(t, calls, 1)
	assert.Equal(t, sessionID, calls[0].SessionID)
	assert.Equal(t, ex.ID, calls[0].ExecutionID)
	assert.Equal(t, "alpha", calls[0].Scanner)
	assert.Len(t, calls[0].Result.Assets, 2)

	// CIDR /29 → 8 ips + raw 127.0.0.1 = 9 exec targets.
	mu.Lock()
	require.Len(t, seenReqs, 1)
	assert.Len(t, seenReqs[0].Targets, 9)
	mu.Unlock()

	// Targets finalized.
	rows, err := db.Query(ctx, `SELECT target, status FROM scan_session_targets WHERE session_id=$1`, sessionID)
	require.NoError(t, err)
	defer rows.Close()
	targetStatus := map[string]string{}
	for rows.Next() {
		var tg, st string
		require.NoError(t, rows.Scan(&tg, &st))
		targetStatus[tg] = st
	}
	assert.Equal(t, "completed", targetStatus["127.0.0.1"])
	assert.Equal(t, "completed", targetStatus["10.9.9.0/29"])

	// SSE wire contract events.
	evs := stop()
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Topic+"/"+e.Kind)
	}
	assert.Contains(t, kinds, "scan/scan.status")
	assert.Contains(t, kinds, "scan/execution.status")
	assert.Contains(t, kinds, "scan/scan.progress")

	var finalPayload map[string]any
	for _, e := range evs {
		if e.Kind == KindScanStatus {
			b, _ := json.Marshal(e.Payload)
			_ = json.Unmarshal(b, &finalPayload)
		}
	}
	require.NotNil(t, finalPayload)
	assert.Equal(t, sessionID.String(), finalPayload["session_id"])
	assert.Equal(t, models.ScanStatusCompleted, finalPayload["status"])
}

func TestOrchestratorPerExecutionFailureDoesNotAbortSiblings(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	ctx := context.Background()

	reg := newFakeRegistry()
	reg.add("good", &fakeScanner{name: "good"}, 30)
	reg.add("bad", &fakeScanner{name: "bad", failWith: errors.New("binary exploded")}, 30)
	sink := &recordingSink{}
	orch, _ := newTestOrchestrator(t, db, reg, sink, nil)

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1"}, []string{"good", "bad", "unregistered-scanner"})
	require.NoError(t, orch.StartSession(ctx, sessionID))
	orch.Wait()

	sm := readSession(t, db, sessionID)
	assert.Equal(t, models.ScanStatusCompletedWithErrors, sm.Status)

	execs := readExecutions(t, db, sessionID)
	require.Len(t, execs, 3)
	byName := map[string]models.ScannerExecution{}
	for _, e := range execs {
		byName[e.ScannerName] = e
	}
	assert.Equal(t, models.ExecStatusCompleted, byName["good"].Status)
	assert.Equal(t, models.ExecStatusFailed, byName["bad"].Status)
	assert.Contains(t, byName["bad"].Error, "binary exploded")
	assert.Equal(t, models.ExecStatusFailed, byName["unregistered-scanner"].Status)
	assert.Contains(t, byName["unregistered-scanner"].Error, "not registered")

	// The good scanner's results are kept.
	require.Len(t, sink.Calls(), 1)
	assert.Equal(t, "good", sink.Calls()[0].Scanner)
}

func TestOrchestratorDenyTargetContinuesOthers(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	ctx := context.Background()

	var mu sync.Mutex
	var gotTargets []string
	reg := newFakeRegistry()
	reg.add("alpha", &fakeScanner{name: "alpha",
		got: func(r scanners.ScanRequest) {
			mu.Lock()
			for _, t := range r.Targets {
				gotTargets = append(gotTargets, t.Raw)
			}
			mu.Unlock()
		}}, 30)
	orch, _ := newTestOrchestrator(t, db, reg, nil,
		allowlistAuthorizer{denied: map[string]string{"evil.example.com": "out of scope"}})

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1", "evil.example.com"}, []string{"alpha"})
	require.NoError(t, orch.StartSession(ctx, sessionID))
	orch.Wait()

	mu.Lock()
	assert.NotContains(t, gotTargets, "evil.example.com")
	assert.Contains(t, gotTargets, "127.0.0.1")
	mu.Unlock()

	var status, errMsg string
	require.NoError(t, db.QueryRow(ctx,
		`SELECT status, error FROM scan_session_targets WHERE session_id=$1 AND target='evil.example.com'`, sessionID).
		Scan(&status, &errMsg))
	assert.Equal(t, "denied", status)
	assert.Contains(t, errMsg, "out of scope")

	sm := readSession(t, db, sessionID)
	assert.Equal(t, models.ScanStatusCompleted, sm.Status, "a denied target does not fail the session")
}

func TestOrchestratorAllTargetsDeniedFailsSession(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	reg := newFakeRegistry()
	reg.add("alpha", &fakeScanner{name: "alpha"}, 30)
	orch, _ := newTestOrchestrator(t, db, reg, nil,
		allowlistAuthorizer{denied: map[string]string{"127.0.0.1": "no"}})

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1"}, []string{"alpha"})
	require.NoError(t, orch.StartSession(context.Background(), sessionID))
	orch.Wait()

	sm := readSession(t, db, sessionID)
	assert.Equal(t, models.ScanStatusFailed, sm.Status)
	assert.Contains(t, sm.Error, "no targets remained")
}

func TestOrchestratorCancel(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	reg := newFakeRegistry()
	reg.add("slow", &fakeScanner{name: "slow", delay: 30 * time.Second}, 60)
	orch, _ := newTestOrchestrator(t, db, reg, nil, nil)

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1"}, []string{"slow"})
	require.NoError(t, orch.StartSession(context.Background(), sessionID))

	// wait until the scanner is actually running
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := reg.Get("slow"); ok && orch.Cancel(sessionID) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session never became cancellable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	orch.Wait()

	sm := readSession(t, db, sessionID)
	assert.Equal(t, models.ScanStatusCancelled, sm.Status)
	// Execution terminal state is written on a detached context; poll briefly.
	var execs []models.ScannerExecution
	settle := time.Now().Add(10 * time.Second)
	for {
		execs = readExecutions(t, db, sessionID)
		if len(execs) == 1 && execs[0].Status != models.ExecStatusQueued {
			break
		}
		if time.Now().After(settle) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Len(t, execs, 1)
	assert.Equal(t, models.ExecStatusCancelled, execs[0].Status)

	assert.False(t, orch.Cancel(uuid.New()), "unknown session is not cancellable")
}

func TestOrchestratorExecutionTimeout(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	reg := newFakeRegistry()
	reg.add("slow", &fakeScanner{name: "slow", delay: 10 * time.Second}, 1) // 1s manifest timeout
	orch, _ := newTestOrchestrator(t, db, reg, nil, nil)

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1"}, []string{"slow"})
	require.NoError(t, orch.StartSession(context.Background(), sessionID))
	done := make(chan struct{})
	go func() { orch.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("per-execution timeout not enforced")
	}

	execs := readExecutions(t, db, sessionID)
	require.Len(t, execs, 1)
	assert.Equal(t, models.ExecStatusFailed, execs[0].Status)
	assert.Contains(t, strings.ToLower(execs[0].Error), "timed out")
}

func TestOrchestratorSinkFailurePreservesRawOutput(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	reg := newFakeRegistry()
	reg.add("alpha", &fakeScanner{name: "alpha"}, 30)
	sink := &recordingSink{err: errors.New("ingest boom")}
	orch, _ := newTestOrchestrator(t, db, reg, sink, nil)

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1"}, []string{"alpha"})
	require.NoError(t, orch.StartSession(context.Background(), sessionID))
	orch.Wait()

	execs := readExecutions(t, db, sessionID)
	require.Len(t, execs, 1)
	assert.Equal(t, models.ExecStatusFailed, execs[0].Status)
	assert.Contains(t, execs[0].Error, "ingestion failed")
	assert.NotEmpty(t, execs[0].RawOutputPath, "raw output preserved despite ingest failure")
	_, err := os.Stat(execs[0].RawOutputPath)
	assert.NoError(t, err)
}

func TestOrchestratorStartSessionOnlyFromQueued(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	reg := newFakeRegistry()
	reg.add("alpha", &fakeScanner{name: "alpha"}, 30)
	orch, _ := newTestOrchestrator(t, db, reg, nil, nil)

	sessionID := mkSession(t, db, projectID, "draft", []string{"127.0.0.1"}, []string{"alpha"})
	err := orch.StartSession(context.Background(), sessionID)
	require.Error(t, err, "draft sessions must be queued first")

	err = orch.StartSession(ctxOrBackground(), uuid.New())
	require.Error(t, err, "unknown sessions must fail")
}

func ctxOrBackground() context.Context { return context.Background() }

func TestOrchestratorExecutionConfigResolution(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	ctx := context.Background()

	// Register the scanner row + project-level configuration in the DB.
	var scannerID uuid.UUID
	require.NoError(t, db.QueryRow(ctx, `
		INSERT INTO scanners (name, display_name, adapter)
		VALUES ('cfgprobe','Cfg Probe','native')
		ON CONFLICT (name) DO UPDATE SET adapter='native' RETURNING id`,
	).Scan(&scannerID))
	_, err := db.Exec(ctx, `
		INSERT INTO scanner_configurations (project_id, scanner_id, config)
		VALUES ($1,$2,'{"ports":"80"}')
		ON CONFLICT (project_id, scanner_id) DO UPDATE SET config='{"ports":"80"}'`,
		projectID, scannerID)
	require.NoError(t, err)

	reg := newFakeRegistry()
	var mu sync.Mutex
	var seenCfg scanners.ScannerConfig
	reg.add("cfgprobe", &fakeScanner{name: "cfgprobe",
		got: func(r scanners.ScanRequest) { mu.Lock(); seenCfg = r.Config; mu.Unlock() }}, 30)
	orch, _ := newTestOrchestrator(t, db, reg, nil, nil)

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1"}, []string{"cfgprobe"})
	require.NoError(t, orch.StartSession(ctx, sessionID))
	orch.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "80", seenCfg["ports"], "project scanner_configurations must flow into execution config")

	// Execution rows were created by the orchestrator.
	execs := readExecutions(t, db, sessionID)
	require.Len(t, execs, 1)
	assert.Equal(t, models.ExecStatusCompleted, execs[0].Status)
}

func TestWorkDirCreated(t *testing.T) {
	db := openTestDB(t)
	projectID := mkProject(t, db)
	var workDirSeen string
	reg := newFakeRegistry()
	reg.add("alpha", &fakeScanner{name: "alpha",
		got: func(r scanners.ScanRequest) { workDirSeen = r.WorkDir }}, 30)
	orch, _ := newTestOrchestrator(t, db, reg, nil, nil)

	sessionID := mkSession(t, db, projectID, "queued", []string{"127.0.0.1"}, []string{"alpha"})
	require.NoError(t, orch.StartSession(context.Background(), sessionID))
	orch.Wait()

	assert.Contains(t, workDirSeen, sessionID.String())
	assert.Contains(t, workDirSeen, string(filepath.Separator))
	info, err := os.Stat(workDirSeen)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
