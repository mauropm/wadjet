package findings

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/assets"
	"github.com/mauropm/wadjet/internal/assets/itest"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
)

func newFindingService(t *testing.T) *Service {
	t.Helper()
	return NewService(itest.DB(), assets.NewService(itest.DB()), nil)
}

// newSession creates a session plus one execution of the given scanner and
// returns both ids.
func newSession(t *testing.T, project uuid.UUID, scanner string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	session := itest.NewScanSession(t, project)
	exec := itest.NewExecution(t, session, scanner)
	return session, exec
}

func assetObs(identity string) scanners.AssetObservationData {
	return scanners.AssetObservationData{
		Identity: identity,
		Ports: []scanners.PortObservation{
			{Port: 443, Protocol: "tcp", State: "open", Service: "https"},
		},
	}
}

func finding(identity, title string, port int, protocol string) scanners.FindingResult {
	p := port
	return scanners.FindingResult{
		Title:       title,
		Description: "initial description",
		Identity:    identity,
		Port:        &p,
		Protocol:    protocol,
		Severity:    models.SeverityHigh,
		Evidence:    scanners.FindingEvidence{Snippet: "evidence-v1"},
	}
}

// TestIngestDeduplicatesAcrossSessions is the headline guarantee: the same
// finding reported by two different sessions produces ONE finding row with TWO
// detection observations, first_detected from the earlier run and last_detected
// from the later one.
func TestIngestDeduplicatesAcrossSessions(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")

	obs := finding("shop.example.com", "TLS certificate expires soon", 443, "tcp")

	firstSession, firstExec := newSession(t, project, "nmap")
	if err := s.Ingest(ctx, firstSession, firstExec, "nmap", &scanners.ScanResult{
		Assets:   []scanners.AssetObservationData{assetObs("shop.example.com")},
		Findings: []scanners.FindingResult{obs},
	}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	if rows := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1`, project); rows != 1 {
		t.Fatalf("findings after first ingest = %d, want 1", rows)
	}
	first, err := s.Get(ctx, onlyFindingID(t, project))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	firstDetected, lastDetected := first.FirstDetected, first.LastDetected
	if first.Status != models.FindingStatusOpen {
		t.Fatalf("new finding status = %q, want open", first.Status)
	}

	time.Sleep(30 * time.Millisecond)

	secondSession, secondExec := newSession(t, project, "nmap")
	if err := s.Ingest(ctx, secondSession, secondExec, "nmap", &scanners.ScanResult{
		Assets:   []scanners.AssetObservationData{assetObs("shop.example.com")},
		Findings: []scanners.FindingResult{obs},
	}); err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1`, project); n != 1 {
		t.Fatalf("findings after second ingest = %d, want 1 (dedup failed)", n)
	}
	reloaded, err := s.Get(ctx, first.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.FirstDetected.Equal(firstDetected) {
		t.Fatalf("first_detected moved: %v -> %v", firstDetected, reloaded.FirstDetected)
	}
	if !reloaded.LastDetected.After(lastDetected) {
		t.Fatalf("last_detected did not advance: %v -> %v", lastDetected, reloaded.LastDetected)
	}
	if !reloaded.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("updated_at did not advance: %v -> %v", first.UpdatedAt, reloaded.UpdatedAt)
	}

	observations, err := s.Observations(ctx, first.ID, 10)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	if len(observations) != 2 {
		t.Fatalf("observations = %d, want 2 (one per detection)", len(observations))
	}
	sessions := map[uuid.UUID]bool{}
	for _, o := range observations {
		if o.ScanSessionID == nil {
			t.Fatalf("observation %s has no session", o.ID)
		}
		sessions[*o.ScanSessionID] = true
		if o.StatusAtDetection != models.FindingStatusOpen {
			t.Fatalf("status_at_detection = %q, want open", o.StatusAtDetection)
		}
		var payload scanners.FindingResult
		if err := json.Unmarshal(o.Raw, &payload); err != nil {
			t.Fatalf("observation raw is not the FindingResult JSON: %v", err)
		}
		if payload.Evidence.Snippet != "evidence-v1" || payload.Title != obs.Title {
			t.Fatalf("observation raw lost evidence: %s", o.Raw)
		}
	}
	if !sessions[firstSession] || !sessions[secondSession] {
		t.Fatalf("observations do not cover both sessions: %v", sessions)
	}

	// Counters: one creation across both sessions, one update, two assets.
	var created, updated, processed int
	if err := itest.DB().QueryRow(ctx,
		`SELECT findings_created, findings_updated, assets_processed FROM scan_sessions WHERE id = $1`,
		firstSession).Scan(&created, &updated, &processed); err != nil {
		t.Fatalf("counters: %v", err)
	}
	if created != 1 || updated != 0 || processed != 1 {
		t.Fatalf("first session counters = %d/%d/%d, want 1/0/1", created, updated, processed)
	}
	if err := itest.DB().QueryRow(ctx,
		`SELECT findings_created, findings_updated, assets_processed FROM scan_sessions WHERE id = $1`,
		secondSession).Scan(&created, &updated, &processed); err != nil {
		t.Fatalf("counters 2: %v", err)
	}
	if created != 0 || updated != 1 || processed != 1 {
		t.Fatalf("second session counters = %d/%d/%d, want 0/1/1", created, updated, processed)
	}
	var execAssets, execFindings int
	if err := itest.DB().QueryRow(ctx,
		`SELECT assets_observed, findings_found FROM scanner_executions WHERE id = $1`, secondExec).
		Scan(&execAssets, &execFindings); err != nil {
		t.Fatalf("execution counters: %v", err)
	}
	if execAssets != 1 || execFindings != 1 {
		t.Fatalf("execution counters = %d/%d, want 1/1", execAssets, execFindings)
	}
}

// TestIngestPortProtocolAndScannerChangesAreDistinctFindings pins that the
// material parts of the fingerprint really separate findings. The scanner name
// comes from the execution, so the cross-scanner case needs its own execution.
func TestIngestPortProtocolAndScannerChangesAreDistinctFindings(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	session, exec := newSession(t, project, "nmap")

	result := &scanners.ScanResult{
		Assets: []scanners.AssetObservationData{assetObs("10.0.0.5")},
		Findings: []scanners.FindingResult{
			finding("10.0.0.5", "Service exposed", 22, "tcp"),
			finding("10.0.0.5", "Service exposed", 2222, "tcp"), // port change
			finding("10.0.0.5", "Service exposed", 22, "udp"),   // protocol change
			finding("10.0.0.5", "  SERVICE   exposed ", 22, "TCP"),
		},
	}
	if err := s.Ingest(ctx, session, exec, "nmap", result); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// The whitespace/case variant dedupes onto tcp/22, so three rows here.
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1`, project); n != 3 {
		t.Fatalf("findings = %d, want 3", n)
	}

	// The same issue reported by another scanner is another finding: two
	// tools agreeing is two pieces of evidence, not one.
	nucleiSession, nucleiExec := newSession(t, project, "nuclei")
	if err := s.Ingest(ctx, nucleiSession, nucleiExec, "nuclei", &scanners.ScanResult{
		Assets:   []scanners.AssetObservationData{assetObs("10.0.0.5")},
		Findings: []scanners.FindingResult{finding("10.0.0.5", "Service exposed", 22, "tcp")},
	}); err != nil {
		t.Fatalf("cross-scanner ingest: %v", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1`, project); n != 4 {
		t.Fatalf("findings after the second scanner = %d, want 4", n)
	}

	fps := map[string]int{}
	rows, err := itest.DB().Query(ctx, `SELECT fingerprint FROM findings WHERE project_id = $1`, project)
	if err != nil {
		t.Fatalf("read fps: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			t.Fatal(err)
		}
		fps[fp]++
	}
	if len(fps) != 4 {
		t.Fatalf("distinct fingerprints = %d, want 4", len(fps))
	}
	for fp, n := range fps {
		if n != 1 {
			t.Fatalf("fingerprint %s has %d rows", fp, n)
		}
	}
	// Two findings of the same asset share the asset scope, proving identity is
	// carried by asset_id rather than by the fingerprint.
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1 AND asset_id = (
		        SELECT id FROM assets WHERE project_id = $1 AND identity = '10.0.0.5')`, project); n != 4 {
		t.Fatalf("findings attached to the asset = %d, want 4", n)
	}
}

// TestIngestReopensRemediatedButKeepsOtherStatuses encodes the verification
// policy: only a remediated finding is reopened by a new detection.
func TestIngestReopensRemediatedButKeepsOtherStatuses(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	session, exec := newSession(t, project, "nmap")

	result := &scanners.ScanResult{
		Assets: []scanners.AssetObservationData{assetObs("db.internal")},
		Findings: []scanners.FindingResult{
			finding("db.internal", "Weak cipher", 443, "tcp"),
			finding("db.internal", "Outdated banner", 80, "tcp"),
			finding("db.internal", "Deprecated header", 8080, "tcp"),
		},
	}
	if err := s.Ingest(ctx, session, exec, "nmap", result); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	remediated := mustFind(t, s, project, "Weak cipher")
	confirmed := mustFind(t, s, project, "Outdated banner")
	accepted := mustFind(t, s, project, "Deprecated header")

	if _, err := s.UpdateStatus(ctx, remediated.ID, models.FindingStatusRemediated, "fixed in build 42", nil); err != nil {
		t.Fatalf("remediate: %v", err)
	}
	if _, err := s.UpdateStatus(ctx, confirmed.ID, models.FindingStatusConfirmed, "verified by analyst", nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := s.UpdateStatus(ctx, accepted.ID, models.FindingStatusAcceptedRisk, "compensating control", nil); err != nil {
		t.Fatalf("accept: %v", err)
	}

	secondSession, secondExec := newSession(t, project, "nmap")
	if err := s.Ingest(ctx, secondSession, secondExec, "nmap", result); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}

	if got := mustGet(t, s, remediated.ID); got.Status != models.FindingStatusOpen {
		t.Fatalf("remediated finding status = %q, want open (must reopen)", got.Status)
	}
	if got := mustGet(t, s, confirmed.ID); got.Status != models.FindingStatusConfirmed {
		t.Fatalf("confirmed finding status = %q, want confirmed (analyst decision kept)", got.Status)
	}
	if got := mustGet(t, s, accepted.ID); got.Status != models.FindingStatusAcceptedRisk {
		t.Fatalf("accepted_risk status = %q, want accepted_risk (analyst decision kept)", got.Status)
	}

	// The reopen must be recorded, attributable and never silent.
	history, err := s.StatusHistory(ctx, remediated.ID)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var reopen *models.FindingStatusHistory
	for i := range history {
		if history[i].ToStatus == models.FindingStatusOpen && history[i].FromStatus == models.FindingStatusRemediated {
			reopen = &history[i]
		}
	}
	if reopen == nil {
		t.Fatalf("no reopen entry in history: %+v", history)
	}
	if !strings.Contains(reopen.Note, "re-detected by scanner nmap") {
		t.Fatalf("reopen note = %q, want it to name the scanner", reopen.Note)
	}
	if reopen.ChangedBy != nil {
		t.Fatalf("a scanner reopen must not claim a user, got %v", reopen.ChangedBy)
	}
	// The confirmed finding gained no history entry from re-detection.
	confirmedHistory, err := s.StatusHistory(ctx, confirmed.ID)
	if err != nil {
		t.Fatalf("confirmed history: %v", err)
	}
	if len(confirmedHistory) != 1 {
		t.Fatalf("confirmed finding gained history rows on re-detection: %+v", confirmedHistory)
	}
	// The re-detected finding keeps its whole detection history.
	if n := observationCount(t, confirmed.ID); n != 2 {
		t.Fatalf("observations = %d, want 2", n)
	}
	// The last observation records the status as it stood at detection time.
	obs, err := s.Observations(ctx, confirmed.ID, 5)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	if obs[0].StatusAtDetection != models.FindingStatusConfirmed {
		t.Fatalf("status_at_detection = %q, want confirmed", obs[0].StatusAtDetection)
	}
}

func TestIngestContentRefreshPolicy(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	session, exec := newSession(t, project, "nmap")

	first := finding("10.0.0.7", "Directory listing", 80, "tcp")
	first.Description = "first seen description"
	first.TechnicalDetails = "initial details"
	first.Evidence = scanners.FindingEvidence{Snippet: "index of /"}
	first.Remediation = ""
	first.References = []string{"https://cwe.mitre.org/548"}

	if err := s.Ingest(ctx, session, exec, "nmap", &scanners.ScanResult{
		Assets:   []scanners.AssetObservationData{assetObs("10.0.0.7")},
		Findings: []scanners.FindingResult{first},
	}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	original := mustFind(t, s, project, "Directory listing")

	second := finding("10.0.0.7", "Directory listing", 80, "tcp")
	second.Description = "rewritten by a newer NSE script"
	second.TechnicalDetails = "updated details"
	second.Evidence = scanners.FindingEvidence{Snippet: "index of /admin"}
	second.Remediation = "disable autoindex"
	second.References = []string{"https://cwe.mitre.org/548", "https://owasp.org/a05"}
	second.Severity = models.SeverityMedium
	second.CVEs = []string{"CVE-2024-1111"}

	secondSession, secondExec := newSession(t, project, "nmap")
	if err := s.Ingest(ctx, secondSession, secondExec, "nmap", &scanners.ScanResult{
		Assets:   []scanners.AssetObservationData{assetObs("10.0.0.7")},
		Findings: []scanners.FindingResult{second},
	}); err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	got := mustGet(t, s, original.ID)
	if got.Description != "first seen description" {
		t.Fatalf("description overwritten: %q", got.Description)
	}
	if got.Title != first.Title {
		t.Fatalf("title overwritten: %q", got.Title)
	}
	if got.Evidence != "index of /admin" {
		t.Fatalf("evidence not refreshed: %q", got.Evidence)
	}
	if got.TechnicalDetails != "updated details" {
		t.Fatalf("technical details not refreshed with the new evidence: %q", got.TechnicalDetails)
	}
	if got.Remediation != "disable autoindex" {
		t.Fatalf("remediation not filled in: %q", got.Remediation)
	}
	if got.Severity != models.SeverityMedium {
		t.Fatalf("severity not refreshed: %q", got.Severity)
	}
	if len(got.CVEs) != 1 || got.CVEs[0] != "CVE-2024-1111" {
		t.Fatalf("cves not refreshed: %v", got.CVEs)
	}
	if !strings.Contains(string(got.References), "owasp") {
		t.Fatalf("references not refreshed: %s", got.References)
	}

	// A later run that reports no evidence must not erase what we know.
	third := finding("10.0.0.7", "Directory listing", 80, "tcp")
	third.Evidence = scanners.FindingEvidence{}
	third.Description = ""
	if err := s.Ingest(ctx, secondSession, secondExec, "nmap", &scanners.ScanResult{
		Assets:   []scanners.AssetObservationData{assetObs("10.0.0.7")},
		Findings: []scanners.FindingResult{third},
	}); err != nil {
		t.Fatalf("third ingest: %v", err)
	}
	after := mustGet(t, s, original.ID)
	if after.Evidence != "index of /admin" {
		t.Fatalf("empty evidence blanked the stored evidence: %q", after.Evidence)
	}
	if after.Description != "first seen description" {
		t.Fatalf("empty description blanked the stored one: %q", after.Description)
	}

	// An unexpected severity from a scanner degrades to info instead of
	// aborting the whole ingest against the CHECK constraint.
	weird := finding("10.0.0.7", "Weird rating", 99, "tcp")
	weird.Severity = "catastrophic"
	if err := s.Ingest(ctx, secondSession, secondExec, "nmap", &scanners.ScanResult{
		Assets:   []scanners.AssetObservationData{assetObs("10.0.0.7")},
		Findings: []scanners.FindingResult{weird},
	}); err != nil {
		t.Fatalf("ingest with odd severity: %v", err)
	}
	if got := mustFind(t, s, project, "Weird rating"); got.Severity != models.SeverityInfo {
		t.Fatalf("odd severity = %q, want info", got.Severity)
	}
}

func TestIngestSkipsFindingWithoutAsset(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	session, exec := newSession(t, project, "nmap")

	err := s.Ingest(ctx, session, exec, "nmap", &scanners.ScanResult{
		Assets: []scanners.AssetObservationData{assetObs("known.example.com")},
		Findings: []scanners.FindingResult{
			finding("ghost.example.com", "Reported for an unobserved host", 443, "tcp"),
			finding("known.example.com", "Reported for an observed host", 443, "tcp"),
		},
	})
	if err != nil {
		t.Fatalf("ingest should skip, not fail: %v", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1`, project); n != 1 {
		t.Fatalf("findings = %d, want 1 (orphan skipped)", n)
	}
	if mustFind(t, s, project, "Reported for an observed host").Title == "" {
		t.Fatal("the valid finding was dropped together with the orphan")
	}
	var created, updated int
	if err := itest.DB().QueryRow(ctx,
		`SELECT findings_created, findings_updated FROM scan_sessions WHERE id = $1`, session).
		Scan(&created, &updated); err != nil {
		t.Fatalf("counters: %v", err)
	}
	if created != 1 || updated != 0 {
		t.Fatalf("counters = %d/%d, want 1/0", created, updated)
	}
}

func TestIngestValidatesInputs(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	session, exec := newSession(t, project, "nmap")
	other := itest.NewProject(t, "")
	otherSession := itest.NewScanSession(t, other)

	if err := s.Ingest(ctx, session, exec, "nmap", nil); !errors.Is(err, ErrEmptyResult) {
		t.Errorf("nil result err = %v, want ErrEmptyResult", err)
	}
	if err := s.Ingest(ctx, uuid.New(), uuid.Nil, "nmap", &scanners.ScanResult{}); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("unknown session err = %v, want ErrSessionNotFound", err)
	}
	// An execution from another session must be refused: results can never be
	// attributed to a session that did not run the scanner.
	if err := s.Ingest(ctx, session, uuid.New(), "nmap", &scanners.ScanResult{}); !errors.Is(err, ErrExecutionMismatch) {
		t.Errorf("foreign execution err = %v, want ErrExecutionMismatch", err)
	}
	otherExec := itest.NewExecution(t, otherSession, "nmap")
	if err := s.Ingest(ctx, session, otherExec, "nmap", &scanners.ScanResult{}); !errors.Is(err, ErrExecutionMismatch) {
		t.Errorf("cross-session execution err = %v, want ErrExecutionMismatch", err)
	}
	if err := s.Ingest(ctx, session, exec, "nmap", &scanners.ScanResult{}); err != nil {
		t.Errorf("empty result err = %v", err)
	}
}

// TestIngestIsAtomic proves the single-transaction requirement: when one asset
// in the payload is unusable, nothing at all is written — not the assets that
// parsed fine, not their observations, not the findings, not the counters.
func TestIngestIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	session, exec := newSession(t, project, "nmap")

	err := s.Ingest(ctx, session, exec, "nmap", &scanners.ScanResult{
		Assets: []scanners.AssetObservationData{
			assetObs("good.example.com"),
			{Identity: "!!! not an identity !!!"},
		},
		Findings: []scanners.FindingResult{finding("good.example.com", "Should vanish", 443, "tcp")},
	})
	if err == nil {
		t.Fatal("ingest with a bad asset identity should fail")
	}
	if n := itest.Count(t, `SELECT count(*) FROM assets WHERE project_id = $1`, project); n != 0 {
		t.Fatalf("assets = %d after a rolled-back ingest, want 0", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1`, project); n != 0 {
		t.Fatalf("findings = %d after a rolled-back ingest, want 0", n)
	}
	var created, processed int
	if err := itest.DB().QueryRow(ctx,
		`SELECT findings_created, assets_processed FROM scan_sessions WHERE id = $1`, session).
		Scan(&created, &processed); err != nil {
		t.Fatalf("counters: %v", err)
	}
	if created != 0 || processed != 0 {
		t.Fatalf("counters survived the rollback: created=%d processed=%d", created, processed)
	}
}

func TestIngestAssetsFeedFindings(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	session, exec := newSession(t, project, "nmap")

	if err := s.Ingest(ctx, session, exec, "nmap", &scanners.ScanResult{
		Assets: []scanners.AssetObservationData{{
			Identity: "2001:DB8::0001", IPv6: "2001:db8::1", MAC: "AA:BB:CC:DD:EE:FF",
			Hostnames: []string{"Host-01.Example.COM"}, OSName: "Linux 6.1", OSAccuracy: 90,
			Ports: []scanners.PortObservation{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}},
		}},
		Findings: []scanners.FindingResult{finding("2001:db8::1", "Weak KEX", 22, "tcp")},
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM assets WHERE project_id = $1`, project); n != 1 {
		t.Fatalf("assets = %d, want 1", n)
	}
	if n := itest.Count(t, `SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id
		WHERE a.project_id = $1 AND a.identity = '2001:db8::1'`, project); n != 1 {
		t.Fatalf("finding not attached to the normalised asset")
	}
	// The asset identity is the reported identity (the address); the hostname
	// travels in its own column.
	asset, err := s.assets.FindByProjectIdentityTx(ctx, itest.DB(), project, "  2001:0DB8::1 ")
	if err != nil {
		t.Fatalf("asset by canonical identity: %v", err)
	}
	if asset.Hostname == nil || *asset.Hostname != "host-01.example.com" {
		t.Fatalf("hostname = %v, want host-01.example.com", asset.Hostname)
	}
	if asset.Domain == nil || *asset.Domain != "example.com" {
		t.Fatalf("domain = %v", asset.Domain)
	}
	if asset.OSName == nil || *asset.OSName != "Linux 6.1" {
		t.Fatalf("os_name = %v", asset.OSName)
	}
	view, err := s.assets.View(ctx, asset.ID)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if len(view.OpenPorts) != 1 || view.OpenPorts[0].Port != 22 {
		t.Fatalf("open ports = %+v", view.OpenPorts)
	}
}

// ───────────────────────────────────────────── helpers

func onlyFindingID(t *testing.T, project uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := itest.DB().QueryRow(context.Background(),
		`SELECT id FROM findings WHERE project_id = $1 LIMIT 1`, project).Scan(&id); err != nil {
		t.Fatalf("finding id: %v", err)
	}
	return id
}

func mustFind(t *testing.T, s *Service, project uuid.UUID, title string) *models.Finding {
	t.Helper()
	var id uuid.UUID
	if err := itest.DB().QueryRow(context.Background(),
		`SELECT id FROM findings WHERE project_id = $1 AND title = $2`, project, title).Scan(&id); err != nil {
		t.Fatalf("find %q: %v", title, err)
	}
	return mustGet(t, s, id)
}

func mustGet(t *testing.T, s *Service, id uuid.UUID) *models.Finding {
	t.Helper()
	f, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get finding %s: %v", id, err)
	}
	return f
}

func observationCount(t *testing.T, findingID uuid.UUID) int {
	t.Helper()
	return itest.Count(t, `SELECT count(*) FROM finding_observations WHERE finding_id = $1`, findingID)
}
