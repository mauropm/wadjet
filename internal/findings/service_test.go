package findings

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/assets/itest"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
)

// seed loads one asset with a few findings of different shapes and returns the
// asset id together with the finding ids by title.
func seed(t *testing.T, s *Service, project uuid.UUID) (uuid.UUID, map[string]*models.Finding) {
	t.Helper()
	ctx := context.Background()
	session, exec := newSession(t, project, "nmap")

	result := &scanners.ScanResult{
		Assets: []scanners.AssetObservationData{assetObs("10.0.0.20")},
		Findings: []scanners.FindingResult{
			finding("10.0.0.20", "Critical RCE", 445, "tcp"),
			finding("10.0.0.20", "Medium disclosure", 80, "tcp"),
			finding("10.0.0.20", "Info banner", 21, "tcp"),
		},
	}
	result.Findings[0].Severity = models.SeverityCritical
	result.Findings[1].Severity = models.SeverityMedium
	result.Findings[1].Description = "directory listing exposes backups"
	result.Findings[2].Severity = models.SeverityInfo
	if err := s.Ingest(ctx, session, exec, "nmap", result); err != nil {
		t.Fatalf("seed ingest: %v", err)
	}
	asset, err := s.assets.FindByProjectIdentityTx(ctx, itest.DB(), project, "10.0.0.20")
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	out := map[string]*models.Finding{}
	for _, title := range []string{"Critical RCE", "Medium disclosure", "Info banner"} {
		out[title] = mustFind(t, s, project, title)
	}
	return asset.ID, out
}

func TestListFiltersAndSorting(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	assetID, ids := seed(t, s, project)

	all, total, err := s.List(ctx, project, Filters{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 || total != 3 {
		t.Fatalf("list = %d/%d, want 3/3", len(all), total)
	}

	bySeverity, n, err := s.List(ctx, project, Filters{Severity: models.SeverityCritical})
	if err != nil || len(bySeverity) != 1 || n != 1 {
		t.Fatalf("severity filter = %d/%d (%v)", len(bySeverity), n, err)
	}
	if bySeverity[0].Title != "Critical RCE" {
		t.Fatalf("severity filter returned %q", bySeverity[0].Title)
	}
	// Filters combine with AND.
	if _, n, err := s.List(ctx, project, Filters{Severity: models.SeverityCritical, Status: models.FindingStatusOpen}); err != nil || n != 1 {
		t.Fatalf("combined filter = %d (%v)", n, err)
	}
	if _, n, err := s.List(ctx, project, Filters{Severity: models.SeverityCritical, Status: models.FindingStatusRemediated}); err != nil || n != 0 {
		t.Fatalf("contradictory filter = %d (%v), want 0", n, err)
	}
	if _, _, err := s.List(ctx, project, Filters{Severity: "apocalyptic"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad severity err = %v", err)
	}

	byStatus, _, err := s.List(ctx, project, Filters{Status: models.FindingStatusOpen})
	if err != nil || len(byStatus) != 3 {
		t.Fatalf("open filter = %d (%v)", len(byStatus), err)
	}
	if _, _, err := s.List(ctx, project, Filters{Status: "todo"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad status err = %v", err)
	}

	byScanner, _, err := s.List(ctx, project, Filters{Scanner: "nmap"})
	if err != nil || len(byScanner) != 3 {
		t.Fatalf("scanner filter = %d (%v)", len(byScanner), err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id=$1 AND scanner='zap'`, project); n != 0 {
		t.Fatal("unexpected zap findings")
	}
	if items, _, err := s.List(ctx, project, Filters{Scanner: "zap"}); err != nil || len(items) != 0 {
		t.Fatalf("unknown scanner filter = %d (%v)", len(items), err)
	}

	byAsset := assetID
	if items, _, err := s.List(ctx, project, Filters{AssetID: &byAsset}); err != nil || len(items) != 3 {
		t.Fatalf("asset filter = %d (%v)", len(items), err)
	}
	foreign := uuid.New()
	if items, _, err := s.List(ctx, project, Filters{AssetID: &foreign}); err != nil || len(items) != 0 {
		t.Fatalf("foreign asset filter = %d (%v)", len(items), err)
	}

	// The free-text filter covers title and description, and is safe against
	// LIKE metacharacters: "100%" must not become a wildcard match.
	q := "backup"
	if items, _, err := s.List(ctx, project, Filters{Query: q}); err != nil || len(items) != 1 {
		t.Fatalf("query filter = %d (%v)", len(items), err)
	}
	if items, _, err := s.List(ctx, project, Filters{Query: "BANNER"}); err != nil || len(items) != 1 {
		t.Fatalf("case-insensitive query = %d (%v)", len(items), err)
	}
	if items, _, err := s.List(ctx, project, Filters{Query: "100%"}); err != nil || len(items) != 0 {
		t.Fatalf("LIKE wildcard leaked: %d (%v)", len(items), err)
	}
	if items, _, err := s.List(ctx, project, Filters{Query: "a_b"}); err != nil || len(items) != 0 {
		t.Fatalf("LIKE single-char wildcard leaked: %d (%v)", len(items), err)
	}

	// Severity sorts by business impact, not alphabetically.
	byImpact, _, err := s.List(ctx, project, Filters{Sort: "severity", Desc: true})
	if err != nil {
		t.Fatalf("severity sort: %v", err)
	}
	if byImpact[0].Title != "Critical RCE" || byImpact[2].Title != "Info banner" {
		t.Fatalf("severity sort order = [%q %q %q]", byImpact[0].Title, byImpact[1].Title, byImpact[2].Title)
	}
	byTitle, _, err := s.List(ctx, project, Filters{Sort: "title", Desc: false})
	if err != nil {
		t.Fatalf("title sort: %v", err)
	}
	if byTitle[0].Title != "Critical RCE" || byTitle[2].Title != "Medium disclosure" {
		t.Fatalf("title sort order = [%q %q %q]", byTitle[0].Title, byTitle[1].Title, byTitle[2].Title)
	}
	if _, _, err := s.List(ctx, project, Filters{Sort: "http_headers"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad sort err = %v", err)
	}

	// Pagination reports the full match count, not just the page size.
	page, total, err := s.List(ctx, project, Filters{Limit: 2, Sort: "title"})
	if err != nil || len(page) != 2 || total != 3 {
		t.Fatalf("page = %d/%d (%v)", len(page), total, err)
	}
	rest, total, err := s.List(ctx, project, Filters{Limit: 2, Offset: 2, Sort: "title"})
	if err != nil || len(rest) != 1 || total != 3 {
		t.Fatalf("second page = %d/%d (%v)", len(rest), total, err)
	}
	if page[0].ID == rest[0].ID {
		t.Fatal("offset returned the same row")
	}

	// Another project's findings never appear.
	other := itest.NewProject(t, "")
	if items, n, err := s.List(ctx, other, Filters{}); err != nil || len(items) != 0 || n != 0 {
		t.Fatalf("cross-project leak: %d/%d (%v)", len(items), n, err)
	}
	_ = ids
}

func TestStatusWorkflow(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	_, ids := seed(t, s, project)

	f := ids["Medium disclosure"]
	analyst := itest.NewUser(t)

	updated, err := s.UpdateStatus(ctx, f.ID, models.FindingStatusConfirmed, "validated manually", &analyst)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if updated.Status != models.FindingStatusConfirmed {
		t.Fatalf("status = %q, want confirmed", updated.Status)
	}
	if updated.UpdatedAt.Before(f.UpdatedAt) {
		t.Fatal("updated_at went backwards")
	}

	history, err := s.StatusHistory(ctx, f.ID)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history = %d rows, want 1", len(history))
	}
	h := history[0]
	if h.FromStatus != models.FindingStatusOpen || h.ToStatus != models.FindingStatusConfirmed {
		t.Fatalf("transition = %q -> %q", h.FromStatus, h.ToStatus)
	}
	if h.Note != "validated manually" {
		t.Fatalf("note = %q", h.Note)
	}
	if h.ChangedBy == nil || *h.ChangedBy != analyst {
		t.Fatalf("changed_by = %v, want %s", h.ChangedBy, analyst)
	}

	// The workflow is not a one-way street: an accepted_risk decision can be
	// reversed, and so can a false_positive.
	for _, status := range []string{models.FindingStatusAcceptedRisk, models.FindingStatusFalsePositive,
		models.FindingStatusRemediated, models.FindingStatusOpen} {
		if _, err := s.UpdateStatus(ctx, f.ID, status, "moving to "+status, &analyst); err != nil {
			t.Fatalf("move to %s: %v", status, err)
		}
		if got := mustGet(t, s, f.ID); got.Status != status {
			t.Fatalf("status = %q, want %q", got.Status, status)
		}
	}
	history, err = s.StatusHistory(ctx, f.ID)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 5 {
		t.Fatalf("history = %d rows, want 5", len(history))
	}
	// Newest first.
	if history[0].ToStatus != models.FindingStatusOpen {
		t.Fatalf("history not newest first: %q", history[0].ToStatus)
	}

	// Re-applying the current status is allowed and still recorded: the history
	// is a faithful log of what the analyst did.
	if _, err := s.UpdateStatus(ctx, f.ID, models.FindingStatusOpen, "double click", &analyst); err != nil {
		t.Fatalf("repeat status: %v", err)
	}
	if history, err := s.StatusHistory(ctx, f.ID); err != nil || len(history) != 6 {
		t.Fatalf("repeat status not recorded: %d (%v)", len(history), err)
	}

	if _, err := s.UpdateStatus(ctx, f.ID, "wontfix", "", &analyst); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown status err = %v, want ErrInvalidInput", err)
	}
	// An actor that is not in users must be refused cleanly: the history table
	// has a foreign key to users and a violation there would be a 500.
	ghost := uuid.New()
	if _, err := s.UpdateStatus(ctx, f.ID, models.FindingStatusOpen, "", &ghost); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown actor err = %v, want ErrInvalidInput", err)
	}
	if got := mustGet(t, s, f.ID); got.Status != models.FindingStatusOpen {
		t.Fatalf("a refused transition changed the finding: %q", got.Status)
	}
	if _, err := s.UpdateStatus(ctx, uuid.New(), models.FindingStatusOpen, "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing finding err = %v, want ErrNotFound", err)
	}

	// The full history endpoint merges both histories and never returns nil
	// arrays in JSON.
	full, err := s.History(ctx, f.ID)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(full.StatusHistory) != 6 || len(full.Observations) != 1 {
		t.Fatalf("history = %d status / %d observations", len(full.StatusHistory), len(full.Observations))
	}
	raw, _ := json.Marshal(full)
	body := string(raw)
	if !strings.Contains(body, `"status_history"`) || !strings.Contains(body, `"observations"`) {
		t.Fatalf("history JSON shape: %s", body)
	}
	if _, err := s.History(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing history err = %v, want ErrNotFound", err)
	}
}

func TestManualCreateSharesTheFingerprintRule(t *testing.T) {
	ctx := context.Background()
	s := newFindingService(t)
	project := itest.NewProject(t, "")
	assetID, ids := seed(t, s, project)

	// A manual entry describing an issue the scanner already reported lands on
	// the SAME row, because the fingerprint rule is shared. The scanner name
	// must match too, so we declare it as nmap.
	_, err := s.Create(ctx, project, ManualInput{
		AssetID: assetID, Title: "  MEDIUM   Disclosure ", Severity: models.SeverityMedium,
		Port: ptrInt(80), Protocol: "TCP", Scanner: "nmap",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate manual finding err = %v, want ErrConflict", err)
	}
	if got := mustGet(t, s, ids["Medium disclosure"].ID); got.Status != models.FindingStatusOpen {
		t.Fatalf("conflicting create changed the finding: %+v", got)
	}

	manual, err := s.Create(ctx, project, ManualInput{
		AssetID: assetID, Title: "Business logic flaw", Description: "coupon stacking",
		Severity: "high", Scanner: "", Note: "found during workshop",
	})
	if err != nil {
		t.Fatalf("manual create: %v", err)
	}
	if manual.Status != models.FindingStatusOpen {
		t.Fatalf("manual status = %q", manual.Status)
	}
	if manual.Scanner != "manual" {
		t.Fatalf("manual scanner = %q, want the manual default", manual.Scanner)
	}
	if manual.Severity != models.SeverityHigh {
		t.Fatalf("manual severity = %q", manual.Severity)
	}
	if manual.Fingerprint != FindingFingerprint("Business logic flaw", "manual", nil, "") {
		t.Fatalf("manual fingerprint is not the shared rule: %s", manual.Fingerprint)
	}
	// Manual entries start their own history, so the triage trail always has a
	// beginning.
	history, err := s.StatusHistory(ctx, manual.ID)
	if err != nil {
		t.Fatalf("manual history: %v", err)
	}
	if len(history) != 1 || history[0].Note != "found during workshop" {
		t.Fatalf("manual history = %+v", history)
	}

	// An unknown severity is normalised rather than rejected with a 500.
	info, err := s.Create(ctx, project, ManualInput{AssetID: assetID, Title: "Cookie without flag", Severity: "MEDIUM!"})
	if err != nil {
		t.Fatalf("create with odd severity: %v", err)
	}
	if info.Severity != models.SeverityInfo {
		t.Fatalf("odd severity = %q, want info", info.Severity)
	}

	if _, err := s.Create(ctx, project, ManualInput{AssetID: assetID, Title: "   "}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("blank title err = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Create(ctx, project, ManualInput{AssetID: uuid.New(), Title: "Orphan"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown asset err = %v, want ErrInvalidInput", err)
	}
	// An asset of another project must not be writable through this project.
	other := itest.NewProject(t, "")
	if _, err := s.Create(ctx, other, ManualInput{AssetID: assetID, Title: "Cross-project"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-project asset err = %v, want ErrInvalidInput", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM findings WHERE project_id = $1`, other); n != 0 {
		t.Fatalf("cross-project create wrote %d findings", n)
	}
}

func TestFindingsHTTPSurface(t *testing.T) {
	s := newFindingService(t)
	r := chi.NewRouter()
	s.Register(r)
	project := itest.NewProject(t, "")
	assetID, ids := seed(t, s, project)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	base := "/projects/" + project.String()
	if rec := do("GET", base+"/findings?severity=critical", ""); rec.Code != http.StatusOK {
		t.Fatalf("list code = %d body = %s", rec.Code, rec.Body)
	} else if !strings.Contains(rec.Body.String(), "Critical RCE") {
		t.Fatalf("list body = %s", rec.Body)
	} else if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("list body lacks the total: %s", rec.Body)
	}
	if rec := do("GET", base+"/findings?sort=bogus", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad sort code = %d, want 400", rec.Code)
	}
	if rec := do("GET", base+"/findings?severity=bogus", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad severity code = %d, want 400", rec.Code)
	}
	if rec := do("GET", base+"/findings?asset_id=not-a-uuid", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad asset_id code = %d, want 400", rec.Code)
	}
	if rec := do("GET", base+"/findings?limit=2&offset=0", ""); rec.Code != http.StatusOK {
		t.Fatalf("paged list code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"total":3`) {
		t.Fatalf("paged list total = %s", rec.Body)
	}

	fid := ids["Info banner"].ID
	// VER-002: a stated project scope that does not own the finding is 404
	// across direct-id routes.
	foreign := itest.NewProject(t, "").String()
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/findings/" + fid.String() + "?project_id=" + foreign, ""},
		{"GET", "/findings/" + fid.String() + "/history?project_id=" + foreign, ""},
		{"PUT", "/findings/" + fid.String() + "/status?project_id=" + foreign, `{"status":"triaged"}`},
	} {
		if rec := do(c.method, c.path, c.body); rec.Code != http.StatusNotFound {
			t.Fatalf("cross-project %s %s code = %d, want 404", c.method, c.path, rec.Code)
		}
	}
	if rec := do("GET", "/findings/"+fid.String()+"?project_id="+project.String(), ""); rec.Code != http.StatusOK {
		t.Fatalf("scoped get code = %d, want 200", rec.Code)
	}
	if rec := do("GET", "/findings/"+fid.String(), ""); rec.Code != http.StatusOK {
		t.Fatalf("get code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"fingerprint"`) {
		t.Fatalf("get body lacks the fingerprint: %s", rec.Body)
	}
	if rec := do("GET", "/findings/"+uuid.NewString(), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing get code = %d", rec.Code)
	}
	if rec := do("GET", "/findings/nope", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad uuid code = %d, want 400", rec.Code)
	}

	// Analyst triage through the API records the acting user: the router runs
	// no auth middleware here, so changed_by stays null but the call succeeds.
	if rec := do("PUT", "/findings/"+fid.String()+"/status", `{"status":"false_positive","note":"expected banner"}`); rec.Code != http.StatusOK {
		t.Fatalf("status code = %d body = %s", rec.Code, rec.Body)
	} else {
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		if out["status"] != "false_positive" {
			t.Fatalf("status = %v", out["status"])
		}
	}
	if rec := do("PUT", "/findings/"+fid.String()+"/status", `{"status":"not-a-status"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad status code = %d, want 400", rec.Code)
	}
	if rec := do("PUT", "/findings/"+fid.String()+"/status", `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body code = %d, want 400", rec.Code)
	}
	if rec := do("PUT", "/findings/"+uuid.NewString()+"/status", `{"status":"open"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("missing finding status code = %d, want 404", rec.Code)
	}

	if rec := do("GET", "/findings/"+fid.String()+"/history", ""); rec.Code != http.StatusOK {
		t.Fatalf("history code = %d", rec.Code)
	} else {
		var out FindingHistory
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode history: %v", err)
		}
		if len(out.StatusHistory) != 1 || out.StatusHistory[0].ToStatus != "false_positive" {
			t.Fatalf("history = %+v", out.StatusHistory)
		}
		if len(out.Observations) != 1 {
			t.Fatalf("observations = %+v", out.Observations)
		}
	}
	if rec := do("GET", "/findings/"+uuid.NewString()+"/history", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing history code = %d, want 404", rec.Code)
	}

	// Manual creation through the API, including the conflict path.
	rec := do("POST", base+"/findings", `{"asset_id":"`+assetID.String()+`","title":"Manual via HTTP","severity":"low","references":["https://example.com/advice"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body = %s", rec.Code, rec.Body)
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created["scanner"] != "manual" {
		t.Fatalf("created scanner = %v", created["scanner"])
	}
	if !strings.Contains(rec.Body.String(), `"references":["https://example.com/advice"]`) {
		t.Fatalf("references not stored as JSON: %s", rec.Body)
	}
	if rec := do("POST", base+"/findings", `{"asset_id":"`+assetID.String()+`","title":"Manual via HTTP"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create code = %d, want 409", rec.Code)
	}
	if rec := do("POST", base+"/findings", `{"asset_id":"`+assetID.String()+`","title":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("blank title code = %d, want 400", rec.Code)
	}
	if rec := do("POST", base+"/findings", `{"title":"no asset"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing asset code = %d, want 400", rec.Code)
	}
}
