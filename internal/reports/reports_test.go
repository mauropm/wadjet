package reports

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/audit"
	"github.com/mauropm/wadjet/internal/config"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
	"github.com/mauropm/wadjet/internal/models"
)

const testDBURL = "postgres://wadjet:***@localhost:5432/wadjet?sslmode=disable"

// openTestDB connects to the shared development database and applies
// migrations. It skips (does not fail) when the database is unreachable so
// the suite still passes in environments without Postgres.
func openTestDB(t *testing.T) *database.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := database.Open(ctx, testDBURL)
	if err != nil {
		t.Skipf("test database unavailable: %v", err)
	}
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// env is a seeded fixture plus the service under test.
type env struct {
	db      *database.DB
	svc     *Service
	bus     *events.Bus
	dir     string
	project uuid.UUID
	session uuid.UUID
	exec    uuid.UUID
	assetA  uuid.UUID // juice.lab web app
	assetB  uuid.UUID // ssh host
	f1      uuid.UUID // critical, juice.lab
	f2      uuid.UUID // high, juice.lab
	f3      uuid.UUID // info, ssh host
}

func setup(t *testing.T) *env {
	t.Helper()
	db := openTestDB(t)
	ctx := context.Background()

	// Sweep leftovers from interrupted runs (cleanup is by project name).
	if _, err := db.Exec(ctx, `DELETE FROM projects WHERE name LIKE 'wadjet-it-%'`); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	e := &env{db: db}
	suffix := fmt.Sprintf("%d-%s", time.Now().UnixNano(), uuid.New().String()[:8])
	name := "wadjet-it-" + suffix

	err := db.QueryRow(ctx,
		`INSERT INTO projects (name, description, tags) VALUES ($1, $2, $3) RETURNING id`,
		"🧪 "+name, "integration test fixture — safe to delete", []string{"test"},
	).Scan(&e.project)
	require.NoError(t, err)
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = db.Exec(cctx, `DELETE FROM projects WHERE name = $1`, "🧪 "+name)
	})

	// Scanner registry entry so methodology shows a real version.
	_, err = db.Exec(ctx,
		`INSERT INTO scanners (name, display_name, version) VALUES ('nmap', 'Nmap', '7.95')
		 ON CONFLICT (name) DO UPDATE SET version = EXCLUDED.version`)
	require.NoError(t, err)

	start := time.Now().Add(-12 * time.Minute)
	finish := start.Add(11*time.Minute + 32*time.Second)
	err = db.QueryRow(ctx,
		`INSERT INTO scan_sessions (project_id, name, status, targets, scanner_names,
		     assets_processed, findings_created, findings_updated,
		     started_at, finished_at, duration_ms)
		 VALUES ($1, 'full sweep', 'completed', $2, $3, 2, 3, 0, $4, $5, $6)
		 RETURNING id`,
		e.project, []string{"172.30.0.0/28"}, []string{"nmap"}, start, finish,
		finish.Sub(start).Milliseconds(),
	).Scan(&e.session)
	require.NoError(t, err)

	_, err = db.Exec(ctx,
		`INSERT INTO scan_session_targets (session_id, target, status, error) VALUES
		 ($1, '172.30.0.0/28', 'completed', ''),
		 ($1, '172.30.0.9', 'failed', 'host timed out')`, e.session)
	require.NoError(t, err)

	// Project-level scope incl. an exclusion.
	_, err = db.Exec(ctx,
		`INSERT INTO project_targets (project_id, target, target_type, excluded, note) VALUES
		 ($1, '172.30.0.0/28', 'cidr', false, 'lab subnet'),
		 ($1, '198.51.100.0/24', 'cidr', true, 'documentation range, never scan')`, e.project)
	require.NoError(t, err)

	err = db.QueryRow(ctx,
		`INSERT INTO scanner_executions (session_id, scanner_name, status, config, targets,
		     raw_output_path, raw_output_bytes, assets_observed, findings_found,
		     started_at, finished_at)
		 VALUES ($1, 'nmap', 'completed', $2, $3, '/data/raw/nmap-1.xml', 48211, 2, 3, $4, $5)
		 RETURNING id`,
		e.session, `{"ports":"1-1000","scripts":"default","timing":"T4"}`,
		[]string{"172.30.0.0/28"}, start, finish,
	).Scan(&e.exec)
	require.NoError(t, err)

	// Assets.
	err = db.QueryRow(ctx,
		`INSERT INTO assets (project_id, identity, asset_type, ip, hostname, os_name, os_accuracy,
		     discovery_source, tags, first_seen, last_seen)
		 VALUES ($1, '172.30.0.10', 'web_app', '172.30.0.10', 'juice.lab', 'Linux 5.10', 92,
		     'scanner', $2, $3, $4) RETURNING id`,
		e.project, []string{"lab"}, start, finish,
	).Scan(&e.assetA)
	require.NoError(t, err)
	err = db.QueryRow(ctx,
		`INSERT INTO assets (project_id, identity, asset_type, ip, hostname,
		     discovery_source, tags)
		 VALUES ($1, '172.30.0.20', 'server', '172.30.0.20', 'ssh.lab', 'scanner', $2)
		 RETURNING id`,
		e.project, []string{"lab"},
	).Scan(&e.assetB)
	require.NoError(t, err)

	// Service observations (raw JSONB in nmap-ish shape).
	_, err = db.Exec(ctx,
		`INSERT INTO asset_observations (asset_id, scan_session_id, scanner_execution_id, observation_type, raw, source) VALUES
		 ($1, $2, $3, 'service',
		  '{"ports":[
		     {"port":3000,"protocol":"tcp","service":"http","state":"open","version":"Node.js Express"},
		     {"port":80,"protocol":"tcp","service":"http","state":"open","version":"nginx 1.25.3"},
		     {"port":9999,"protocol":"tcp","service":"unknown","state":"closed"}]}', 'nmap'),
		 ($4, $2, $3, 'service',
		  '{"ports":[
		     {"port":2222,"protocol":"tcp","service":"ssh","state":"open","version":"OpenSSH 7.7 protocol 2.0"}]}', 'nmap')`,
		e.assetA, e.session, e.exec, e.assetB)
	require.NoError(t, err)

	// Findings (realistic, untrusted-looking text incl. ANSI escapes, emoji,
	// a giant single token, CRLF, zero-width characters).
	e.f1 = seedFinding(t, db, e.project, e.assetA, "Critical",
		"Remote code execution via unsanitized upload 🧨\x1b[31m",
		"Attacker-controlled archive files are extracted without validation.",
		"POST /files/upload multipart filename traversal. Stack: eval() at app.js:42.",
		"HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\n\n$ id\nuid=0(root)​ gid=0(root)\n"+
			strings.Repeat("A", 12000)+"\n",
		[]string{"CVE-2024-12345", "CVE-2023-99999"}, 9.8, "critical", "nmap",
		3000, "tcp", "http", `["https://owasp.org/Top10/","https://nvd.nist.gov/vuln/detail/CVE-2024-12345"]`)
	e.f2 = seedFinding(t, db, e.project, e.assetA, "High",
		"Outdated TLS configuration",
		"The endpoint negotiates deprecated cipher suites.",
		"TLS 1.0 and 1.1 accepted.",
		"Supported cipher suites:\n  TLS_RSA_WITH_RC4_128_SHA (deprecated)",
		[]string{"CVE-2021-3450"}, 7.5, "high", "nmap", 3000, "tcp", "http", `[]`)
	e.f3 = seedFinding(t, db, e.project, e.assetB, "Info",
		"SSH banner discloses software version",
		"", "", "SSH-2.0-OpenSSH_7.7", nil, 0, "info", "nmap", 2222, "tcp", "ssh", `[]`)
	// (the 0 above is unused CVSS → replaced by nil inside seedFinding for info)

	// Detection observations bind findings to the session/execution.
	for _, f := range []uuid.UUID{e.f1, e.f2, e.f3} {
		_, err = db.Exec(ctx,
			`INSERT INTO finding_observations (finding_id, scan_session_id, scanner_execution_id, status_at_detection, raw)
			 VALUES ($1, $2, $3, 'open', $4)`,
			f, e.session, e.exec, `{"reason":"seed"}`)
		require.NoError(t, err)
	}
	_, err = db.Exec(ctx,
		`INSERT INTO finding_status_history (finding_id, from_status, to_status, note) VALUES
		 ($1, '', 'open', 'first detected'),
		 ($1, 'open', 'confirmed', 'verified by analyst')`, e.f1)
	require.NoError(t, err)

	// Service.
	e.dir = t.TempDir()
	e.bus = events.New()
	e.svc = NewService(db, &config.Config{ReportDir: e.dir}, e.bus, audit.NewLogger(db))

	t.Cleanup(func() { e.svc.Wait() })
	return e
}

// seedFinding inserts one finding with untrusted-shaped text and returns its id.
func seedFinding(t *testing.T, db *database.DB, project, asset uuid.UUID, tag, ttl, desc, tech,
	ev []string, cves []string, score float64, sev, scanner string, port int, proto, svcName, refs string,
) uuid.UUID {
	t.Helper()
	var cvss any
	if score > 0 {
		cvss = score
	}
	var id uuid.UUID
	err := db.QueryRow(context.Background(),
		`INSERT INTO findings (project_id, asset_id, title, description, technical_details, evidence,
		     scanner, port, protocol, service, cves, cvss_score, severity, status, remediation,
		     "references", fingerprint)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'open',$14,$15,$16) RETURNING id`,
		project, asset, ttl, desc, tech, ev, scanner, port, proto, svcName, cves, cvss, sev,
		"Upgrade the affected component and re-scan.", refs, "fp-"+tag+"-"+uuid.New().String()[:8],
	).Scan(&id)
	require.NoError(t, err)
	return id
}

func (e *env) router() http.Handler {
	r := chi.NewRouter()
	e.svc.Register(r)
	return r
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// waitReport polls until the report reaches a terminal state.
func waitReport(t *testing.T, db *database.DB, id uuid.UUID) models.Report {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var r models.Report
		err := db.QueryRow(context.Background(),
			`SELECT id, project_id, session_id, finding_id, type, status, file_path, file_size,
			        error, created_at, completed_at
			 FROM reports WHERE id = $1`, id).
			Scan(&r.ID, &r.ProjectID, &r.SessionID, &r.FindingID, &r.Type, &r.Status,
				&r.FilePath, &r.FileSize, &r.Error, &r.CreatedAt, &r.CompletedAt)
		require.NoError(t, err)
		if r.Status == models.ReportStatusCompleted || r.Status == models.ReportStatusFailed {
			require.NotEqualf(t, models.ReportStatusFailed, r.Status, "generation failed: %s", r.Error)
			return r
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("report %s did not reach a terminal state", id)
	return models.Report{}
}

func decodeReport(t *testing.T, rec *httptest.ResponseRecorder) models.Report {
	t.Helper()
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var r models.Report
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &r))
	return r
}

func assertPDF(t *testing.T, blob []byte) {
	t.Helper()
	require.Greater(t, len(blob), 1000, "PDF suspiciously small")
	assert.True(t, bytes.HasPrefix(blob, []byte("%PDF-")), "missing %PDF header")
	assert.True(t, bytes.Contains(blob, []byte("%%EOF")), "missing EOF marker")
}

// ───────────────────────────────────────────── tests

func TestScanReportLifecycle(t *testing.T) {
	e := setup(t)
	h := e.router()

	// SSE contract check.
	ch, cancel := e.bus.Subscribe()
	defer cancel()

	rec := do(t, h, "POST", "/projects/"+e.project.String()+"/reports/scan",
		`{"session_id":"`+e.session.String()+`"}`)
	rpt := decodeReport(t, rec)
	assert.Equal(t, models.ReportTypeScan, rpt.Type)
	assert.Equal(t, models.ReportStatusPending, rpt.Status)

	done := waitReport(t, e.db, rpt.ID)
	assert.Equal(t, models.ReportStatusCompleted, done.Status)
	require.NotNil(t, done.CompletedAt)
	assert.Greater(t, done.FileSize, int64(1000))

	// File naming: <project-slug>/<type>-<id>-<stamp>.pdf, slug from 🧪 name.
	slug := slugify("🧪 wadjet-it-lifecycle") // sanity: emoji collapses
	assert.NotEmpty(t, slug)
	assert.True(t, strings.HasPrefix(done.FilePath, "wadjet-it-"), done.FilePath)
	assert.Contains(t, done.FilePath, "scan-"+rpt.ID.String())
	assert.True(t, strings.HasSuffix(done.FilePath, ".pdf"))

	blob, err := os.ReadFile(filepath.Join(e.dir, filepath.FromSlash(done.FilePath)))
	require.NoError(t, err)
	assert.Equal(t, done.FileSize, int64(len(blob)))
	assertPDF(t, blob)
	// Content pages must carry the WADJET branding strings.
	assert.Contains(t, string(blob), "WADJET")

	// Download path.
	rec = do(t, h, "GET", "/reports/"+rpt.ID.String()+"/download", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/pdf", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), `attachment; filename="`)
	assert.Equal(t, len(blob), rec.Body.Len())

	// List endpoints.
	rec = do(t, h, "GET", "/reports?project_id="+e.project.String()+"&type=scan", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		Items []models.Report `json:"items"`
		Total int             `json:"total"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Equal(t, 1, list.Total)
	assert.Equal(t, rpt.ID, list.Items[0].ID)

	// Events: at least one report.status with the completed file_size.
	drainWait(e.bus, ch, rpt.ID, models.ReportStatusCompleted, done.FileSize, t)
}

func drainWait(bus *events.Bus, ch <-chan events.Event, id uuid.UUID, wantStatus string, wantSize int64, t *testing.T) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	found := false
	for !found {
		select {
		case ev := <-ch:
			if ev.Topic != "report" || ev.Kind != "report.status" {
				continue
			}
			m, ok := ev.Payload.(map[string]any)
			if !ok {
				continue
			}
			if fmt.Sprint(m["report_id"]) != id.String() {
				continue
			}
			if m["status"] == wantStatus {
				if fs, ok := m["file_size"].(int64); ok {
					require.Equal(t, wantSize, fs)
				} else if fs, ok := m["file_size"].(float64); ok {
					require.EqualValues(t, wantSize, fs)
				} else {
					t.Fatalf("file_size missing in event payload")
				}
				require.NotEmpty(t, m["project_id"])
				found = true
			}
		case <-deadline:
			t.Fatalf("no completed report.status event received for %s", id)
		}
	}
	_ = bus
}

func TestFindingAdvisoryAndIsolation(t *testing.T) {
	e := setup(t)
	h := e.router()

	rec := do(t, h, "POST", "/findings/"+e.f1.String()+"/report", `{}`)
	rpt := decodeReport(t, rec)
	assert.Equal(t, models.ReportTypeFinding, rpt.Type)
	done := waitReport(t, e.db, rpt.ID)
	require.NotNil(t, done.FindingID)

	blob, err := os.ReadFile(filepath.Join(e.dir, filepath.FromSlash(done.FilePath)))
	require.NoError(t, err)
	assertPDF(t, blob)

	rec = do(t, h, "GET", "/reports/"+rpt.ID.String()+"/download", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Disposition"), ".pdf")

	// Cross-project isolation: another project must not see this report.
	var other uuid.UUID
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ('wadjet-it-other') RETURNING id`).Scan(&other))
	t.Cleanup(func() {
		_, _ = e.db.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, other)
	})
	rec = do(t, h, "GET", "/reports/"+rpt.ID.String()+"?project_id="+other.String(), "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = do(t, h, "GET", "/reports/"+rpt.ID.String()+"/download?project_id="+other.String(), "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Forged chain: report row claims the foreign project though its
	// session belongs to e.project → 404.
	var forged uuid.UUID
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO reports (project_id, session_id, type, status) VALUES ($1, $2, 'scan', 'completed') RETURNING id`,
		other, e.session).Scan(&forged))
	rec = do(t, h, "GET", "/reports/"+forged.String()+"/download", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Not completed → refused.
	var pend uuid.UUID
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO reports (project_id, type, status) VALUES ($1, 'scan', 'pending') RETURNING id`,
		e.project).Scan(&pend))
	rec = do(t, h, "GET", "/reports/"+pend.String()+"/download", "")
	assert.Equal(t, http.StatusConflict, rec.Code)

	// Completed row whose file vanished → 404.
	var ghost uuid.UUID
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO reports (project_id, type, status, file_path, file_size)
		 VALUES ($1, 'scan', 'completed', 'nope/x.pdf', 123) RETURNING id`,
		e.project).Scan(&ghost))
	rec = do(t, h, "GET", "/reports/"+ghost.String()+"/download", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	// Bad ids.
	rec = do(t, h, "GET", "/reports/not-a-uuid", "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestFindingsZipAndConsolidated(t *testing.T) {
	e := setup(t)
	h := e.router()

	// ZIP (consolidated=false) filtered to critical+high.
	rec := do(t, h, "POST", "/projects/"+e.project.String()+"/reports/findings",
		`{"consolidated":false,"severity":["critical","high"]}`)
	rpt := decodeReport(t, rec)
	assert.Equal(t, models.ReportTypeFindingsZip, rpt.Type)
	done := waitReport(t, e.db, rpt.ID)
	assert.True(t, strings.HasSuffix(done.FilePath, ".zip"), done.FilePath)

	blob, err := os.ReadFile(filepath.Join(e.dir, filepath.FromSlash(done.FilePath)))
	require.NoError(t, err)
	require.Greater(t, len(blob), 2000)
	require.True(t, bytes.HasPrefix(blob, []byte("PK")), "missing ZIP magic")

	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	require.NoError(t, err)
	var names []string
	var manifest []byte
	for _, f := range zr.File {
		names = append(names, f.Name)
		if f.Name == "manifest.csv" {
			rc, err := f.Open()
			require.NoError(t, err)
			manifest, err = io.ReadAll(rc)
			rc.Close()
			require.NoError(t, err)
		}
	}
	assert.Contains(t, names, "manifest.csv")
	pdfCount := 0
	for _, n := range names {
		if strings.HasPrefix(n, "findings/FND-") && strings.HasSuffix(n, ".pdf") {
			pdfCount++
		}
	}
	assert.Equal(t, 2, pdfCount, "one advisory per matching finding: %v", names)
	assert.Contains(t, string(manifest), "finding_id,title,severity,asset,fingerprint")
	assert.Contains(t, string(manifest), "critical")
	assert.NotContains(t, string(manifest), "SSH banner", "info finding must be filtered out")

	rec = do(t, h, "GET", "/reports/"+rpt.ID.String()+"/download", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/zip", rec.Header().Get("Content-Type"))

	// Consolidated single PDF.
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/findings",
		`{"consolidated":true}`)
	cons := decodeReport(t, rec)
	assert.Equal(t, models.ReportTypeFindingsConsolidated, cons.Type)
	done = waitReport(t, e.db, cons.ID)
	blob, err = os.ReadFile(filepath.Join(e.dir, filepath.FromSlash(done.FilePath)))
	require.NoError(t, err)
	assertPDF(t, blob)

	// Asset-scoped report.
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/findings",
		`{"consolidated":true,"asset_id":"`+e.assetB.String()+`"}`)
	r2 := decodeReport(t, rec)
	waitReport(t, e.db, r2.ID)

	// Zero-match scope → 422; unknown severity → 400.
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/findings",
		`{"consolidated":true,"severity":["info"],"asset_id":"`+e.assetA.String()+`"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/findings",
		`{"consolidated":true,"severity":["catastrophic"]}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Cross-project asset id → 404.
	var other uuid.UUID
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ('wadjet-it-x') RETURNING id`).Scan(&other))
	defer func() {
		_, _ = e.db.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, other)
	}()
	rec = do(t, h, "POST", "/projects/"+other.String()+"/reports/findings",
		`{"consolidated":true,"asset_id":"`+e.assetA.String()+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestMaliciousInputSurvivesAllRenderers(t *testing.T) {
	e := setup(t)
	h := e.router()

	// A finding with adversarial text (huge token, ANSI escapes, RTL mark,
	// CRLF, emoji, empty evidence edge cases).
	nasty := uuid.UUID{}
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO findings (project_id, asset_id, title, description, technical_details, evidence,
		     scanner, port, protocol, service, cves, cvss_score, severity, status, remediation,
		     "references", fingerprint)
		 VALUES ($1,$2,$3,$4,$5,$6,'evil',null,null,null,$7,null,'critical','open',$8,$9,$10)
		 RETURNING id`,
		e.project, e.assetA,
		strings.Repeat("👁", 400),                         // 400 runes of emoji title
		strings.Repeat("desc\u202e", 900),                 // RTL override spam
		"\x00\x01\x02 binary junk \x7f" + strings.Repeat("x", 6000), // tech details junk
		"BEGIN\n"+strings.Repeat("ZZZ-", 5000)+"\nEND\r\n\t tabbed \x1b[2J",
		[]string{"CVE-1-1"},
		"fix it",
		`{"weird":"not an array","items":[{"url":"https://example.com/ref","x":1}]}`,
		"fp-nasty",
	).Scan(&nasty))

	// Single finding PDF.
	rec := do(t, h, "POST", "/findings/"+nasty.String()+"/report", `{}`)
	rpt := decodeReport(t, rec)
	done := waitReport(t, e.db, rpt.ID)
	blob, err := os.ReadFile(filepath.Join(e.dir, filepath.FromSlash(done.FilePath)))
	require.NoError(t, err)
	assertPDF(t, blob)

	// Consolidated + ZIP over the whole project (incl. the nasty finding).
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/findings",
		`{"consolidated":true}`)
	rpt2 := decodeReport(t, rec)
	waitReport(t, e.db, rpt2.ID)
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/findings",
		`{"consolidated":false}`)
	rpt3 := decodeReport(t, rec)
	waitReport(t, e.db, rpt3.ID)

	// Scan report too.
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/scan",
		`{"session_id":"`+e.session.String()+`"}`)
	rpt4 := decodeReport(t, rec)
	waitReport(t, e.db, rpt4.ID)
}

func TestValidationAndNotFoundPaths(t *testing.T) {
	e := setup(t)
	h := e.router()

	// Missing session.
	rec := do(t, h, "POST", "/projects/"+e.project.String()+"/reports/scan", `{}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	// Unknown session.
	rec = do(t, h, "POST", "/projects/"+e.project.String()+"/reports/scan",
		`{"session_id":"`+uuid.NewString()+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	// Session from another project.
	var other uuid.UUID
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO projects (name) VALUES ('wadjet-it-v') RETURNING id`).Scan(&other))
	defer func() { _, _ = e.db.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, other) }()
	rec = do(t, h, "POST", "/projects/"+other.String()+"/reports/scan",
		`{"session_id":"`+e.session.String()+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	// Unknown project.
	rec = do(t, h, "POST", "/projects/"+uuid.NewString()+"/reports/scan",
		`{"session_id":"`+e.session.String()+`"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	// Unknown finding.
	rec = do(t, h, "POST", "/findings/"+uuid.NewString()+"/report", `{}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	// Bad type filter.
	rec = do(t, h, "GET", "/reports?type=nope", "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestQueuedReportsSurviveAsFiles verifies completed reports are readable
// from disk through a fresh service instance (restart simulation).
func TestCompletedReportsSurviveRestart(t *testing.T) {
	e := setup(t)
	h := e.router()
	rec := do(t, h, "POST", "/findings/"+e.f3.String()+"/report", `{}`)
	rpt := decodeReport(t, rec)
	done := waitReport(t, e.db, rpt.ID)

	// New service instance over the same report dir (process restart).
	fresh := NewService(e.db, &config.Config{ReportDir: e.dir}, events.New(), audit.NewLogger(e.db))
	fr := chi.NewRouter()
	fresh.Register(fr)
	rec = do(t, fr, "GET", "/reports/"+rpt.ID.String()+"/download", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int(done.FileSize), rec.Body.Len())

	// A stale 'generating' row from the "crashed" process is failed.
	var stale uuid.UUID
	require.NoError(t, e.db.QueryRow(context.Background(),
		`INSERT INTO reports (project_id, type, status) VALUES ($1,'scan','generating') RETURNING id`,
		e.project).Scan(&stale))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var st, er string
		require.NoError(t, e.db.QueryRow(context.Background(),
			`SELECT status, error FROM reports WHERE id=$1`, stale).Scan(&st, &er))
		if st == "failed" {
			assert.Contains(t, er, "restart")
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("stale generating row was not failed by recovery")
}

// TestRenderScanReportBytesLayout exercises the renderer directly with
// adversarial synthetic structures (pure layout test, no DB).
func TestRenderScanReportBytesLayout(t *testing.T) {
	d := &scanData{
		Project: models.Project{ID: uuid.New(), Name: "🧪 Layout Lab 👁️"},
		Session: models.ScanSession{ID: uuid.New(), ProjectID: uuid.New(), Status: "completed",
			Targets: []string{"10.0.0.0/24"}, ScannerNames: []string{"nmap"}},
		Assets: []assetView{{Asset: models.Asset{
			ID: uuid.New(), Identity: strings.Repeat("h", 300), AssetType: "server",
			FirstSeen: time.Now(), LastSeen: time.Now(),
		}, Ports: []observedPort{{Port: 1, Protocol: "tcp", Service: strings.Repeat("S", 900), State: "open", Version: strings.Repeat("V", 500)}}}},
		Findings: []findingView{{
			Finding: models.Finding{
				ID: uuid.New(), Title: strings.Repeat("T", 900), Severity: "critical",
				Evidence: strings.Repeat("E", 9000), Description: strings.Repeat("D", 6000),
				TechnicalDetails: strings.Repeat("X", 12000), CVEs: []string{"CVE-2024-00001", "junk"},
				References: json.RawMessage(`["https://x.example/` + strings.Repeat("a", 600) + `"]`),
			},
			Seq: 1, AssetIdentity: "10.0.0.1",
		}},
	}
	d.Session.Name = strings.Repeat("session", 200)
	blob := renderScanReportBytes(d, time.Now())
	assertPDF(t, blob)
}
