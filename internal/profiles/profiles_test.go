package profiles

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
)

func newService() *Service { return NewService(itest.DB()) }

// scanner creates a registry entry and returns its id. Names are globally
// unique, so every call mints a fresh one.
func scanner(t *testing.T) uuid.UUID {
	t.Helper()
	return itest.NewScanner(t, "")
}

// setScannerState moves a registry entry out of the available state, the way a
// failed health check would.
func setScannerState(t *testing.T, id uuid.UUID, status string, enabled bool) {
	t.Helper()
	itest.MustExec(t, `UPDATE scanners SET status = $2, enabled = $3 WHERE id = $1`, id, status, enabled)
}

func TestCreateAttachesScannersAndAppliesDefaults(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	nmap, nuclei := scanner(t), scanner(t)

	created, err := s.Create(ctx, project, CreateInput{
		Name:            "External full",
		Description:     "external perimeter, all scanners",
		TargetSelection: []string{" example.com ", "example.com", "", "shop.example.com"},
		ExcludedTargets: []string{"10.0.0.0/8"},
		ReportPrefs:     json.RawMessage(`{"sections":["exec","technical"],"format":"pdf"}`),
		Scanners: []ScannerBinding{
			{ScannerID: nmap, Config: json.RawMessage(`{"top_ports":1000}`), SortOrder: 0},
			{ScannerID: nuclei, Config: json.RawMessage(`{"severity":"high"}`), SortOrder: 1},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Name != "External full" || created.ProjectID != project {
		t.Fatalf("profile = %+v", created)
	}
	if created.TimeoutSeconds != defaultTimeout {
		t.Fatalf("timeout_seconds = %d, want the %ds default", created.TimeoutSeconds, defaultTimeout)
	}
	// Duplicates and blanks are dropped from the target lists, order preserved.
	if strings.Join(created.TargetSelection, "|") != "example.com|shop.example.com" {
		t.Fatalf("target_selection = %v", created.TargetSelection)
	}
	if strings.Join(created.ExcludedTargets, "|") != "10.0.0.0/8" {
		t.Fatalf("excluded_targets = %v", created.ExcludedTargets)
	}
	if !strings.Contains(string(created.ReportPrefs), `"pdf"`) {
		t.Fatalf("report_prefs = %s", created.ReportPrefs)
	}
	if len(created.Scanners) != 2 {
		t.Fatalf("scanners = %+v, want 2", created.Scanners)
	}
	// The bindings carry the denormalised scanner name and their own config.
	for _, b := range created.Scanners {
		if b.ProfileID != created.ID {
			t.Fatalf("binding %s has profile_id %s", b.ID, b.ProfileID)
		}
		if b.Scanner == "" {
			t.Fatalf("binding %s lost the scanner name", b.ID)
		}
		var cfg map[string]any
		if err := json.Unmarshal(b.Config, &cfg); err != nil {
			t.Fatalf("config %s is not JSON: %v", b.Config, err)
		}
		if len(cfg) != 1 {
			t.Fatalf("config %s was rewritten: %v", b.Config, cfg)
		}
	}
	if created.Scanners[0].SortOrder > created.Scanners[1].SortOrder {
		t.Fatalf("bindings are not ordered by sort_order: %+v", created.Scanners)
	}

	// The row and the binding rows really exist.
	if n := itest.Count(t, `SELECT count(*) FROM scan_profile_scanners WHERE profile_id = $1`, created.ID); n != 2 {
		t.Fatalf("binding rows = %d, want 2", n)
	}
	reloaded, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(reloaded.Scanners) != 2 {
		t.Fatalf("get returned %d bindings", len(reloaded.Scanners))
	}
}

func TestCreateValidation(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")

	cases := []struct {
		why  string
		in   CreateInput
		want error
	}{
		{"blank name", CreateInput{Name: "   "}, ErrInvalidInput},
		{"over-long name", CreateInput{Name: strings.Repeat("n", maxNameLength+1)}, ErrInvalidInput},
		{"multi-line name", CreateInput{Name: "two\nlines"}, ErrInvalidInput},
		{"over-long description", CreateInput{Name: "ok", Description: strings.Repeat("d", maxDescriptionLen+1)}, ErrInvalidInput},
		{"timeout below range", CreateInput{Name: "ok", TimeoutSeconds: 0}, nil}, // 0 means the default
		{"timeout too small", CreateInput{Name: "ok", TimeoutSeconds: -5}, ErrInvalidInput},
		{"timeout too large", CreateInput{Name: "ok", TimeoutSeconds: maxTimeoutSeconds + 1}, ErrInvalidInput},
		{"broken report_prefs", CreateInput{Name: "ok", ReportPrefs: json.RawMessage(`{"a":}`)}, ErrInvalidInput},
		{"scanner without id", CreateInput{Name: "ok", Scanners: []ScannerBinding{{}}}, ErrInvalidInput},
	}
	for _, tc := range cases {
		_, err := s.Create(ctx, project, tc.in)
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.why, err)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.why, err, tc.want)
		}
	}
	// The default-timeout case above left a profile behind; clean it up so the
	// name-reuse checks below are predictable.
	itest.MustExec(t, `DELETE FROM scan_profiles WHERE project_id = $1 AND name = 'ok'`, project)

	// An unknown project is not a valid scope for a profile.
	if _, err := s.Create(ctx, uuid.New(), CreateInput{Name: "orphan"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown project err = %v, want ErrNotFound", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scan_profiles WHERE name = 'orphan'`); n != 0 {
		t.Errorf("profile created for an unknown project")
	}
}

func TestCreateValidatesScannerBindings(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	good := scanner(t)

	// A scanner id that is not in the registry: the profile cannot run, and a
	// typo must not be stored to fail later at scan time.
	if _, err := s.Create(ctx, project, CreateInput{
		Name: "ghost", Scanners: []ScannerBinding{{ScannerID: uuid.New()}}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown scanner err = %v, want ErrNotFound", err)
	}
	// Nothing may be stored when the bindings are rejected.
	if n := itest.Count(t, `SELECT count(*) FROM scan_profiles WHERE name = 'ghost'`); n != 0 {
		t.Errorf("profile stored despite a rejected scanner")
	}
	// The same scanner twice in one request.
	if _, err := s.Create(ctx, project, CreateInput{
		Name: "dup", Scanners: []ScannerBinding{{ScannerID: good}, {ScannerID: good}}}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("duplicate scanner err = %v, want ErrInvalidInput", err)
	}
	// A scanner config must be an object: options are a map.
	for _, bad := range []string{`["not","an","object"]`, `"string"`, `42`, `{`, `{"unterminated":1`} {
		if _, err := s.Create(ctx, project, CreateInput{
			Name: "cfg", Scanners: []ScannerBinding{{ScannerID: good, Config: json.RawMessage(bad)}}}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("config %s err = %v, want ErrInvalidInput", bad, err)
		}
	}
	// A missing config is fine and becomes the empty object.
	empty, err := s.Create(ctx, project, CreateInput{Name: "cfg", Scanners: []ScannerBinding{{ScannerID: good}}})
	if err != nil {
		t.Fatalf("create with empty config: %v", err)
	}
	if string(empty.Scanners[0].Config) != "{}" {
		t.Fatalf("empty config = %s, want {}", empty.Scanners[0].Config)
	}
	// A negative sort order is rejected rather than silently clamped.
	if _, err := s.Create(ctx, project, CreateInput{
		Name: "neg", Scanners: []ScannerBinding{{ScannerID: good, SortOrder: -1}}}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("negative sort_order err = %v, want ErrInvalidInput", err)
	}
	// Too many scanners is a mistake, not a strategy.
	many := make([]ScannerBinding, maxScanners+1)
	for i := range many {
		many[i] = ScannerBinding{ScannerID: uuid.New()}
	}
	if _, err := s.Create(ctx, project, CreateInput{Name: "many", Scanners: many}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("too many scanners err = %v, want ErrInvalidInput", err)
	}
}

// TestCreateRefusesUnavailableScanners proves a profile cannot be authored with
// a scanner the platform knows it cannot run: binding it is a clear error now,
// not a scan that silently skips it later.
func TestCreateRefusesUnavailableScanners(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")

	for _, tc := range []struct {
		why     string
		status  string
		enabled bool
	}{
		{"disabled by health check", "disabled", true},
		{"executable missing", "missing", true},
		{"last probe errored", "error", true},
		{"switched off", "available", false},
	} {
		id := scanner(t)
		setScannerState(t, id, tc.status, tc.enabled)
		_, err := s.Create(ctx, project, CreateInput{Name: "refuse-" + tc.why, Scanners: []ScannerBinding{{ScannerID: id}}})
		if !errors.Is(err, ErrConflict) {
			t.Errorf("%s: err = %v, want ErrConflict", tc.why, err)
		}
	}
	// A scanner that has never been probed is still bindable: 'unknown' is the
	// state of a freshly installed registry, and refusing it would make the
	// platform unusable before the first health check.
	unknown := scanner(t)
	setScannerState(t, unknown, "unknown", true)
	if _, err := s.Create(ctx, project, CreateInput{Name: "unknown-ok", Scanners: []ScannerBinding{{ScannerID: unknown}}}); err != nil {
		t.Errorf("unknown status should be bindable: %v", err)
	}
}

func TestNameUniquenessPerProject(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	other := itest.NewProject(t, "")

	if _, err := s.Create(ctx, project, CreateInput{Name: "Weekly external"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := s.Create(ctx, project, CreateInput{Name: "Weekly external"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name err = %v, want ErrConflict", err)
	}
	// Surrounding spaces are trimmed, so they do not smuggle a duplicate in.
	if _, err := s.Create(ctx, project, CreateInput{Name: "  Weekly external  "}); !errors.Is(err, ErrConflict) {
		t.Fatalf("padded duplicate err = %v, want ErrConflict", err)
	}
	// Case is not a difference an assessor intends: "Weekly external" and
	// "WEEKLY EXTERNAL" would be indistinguishable in the UI.
	if _, err := s.Create(ctx, project, CreateInput{Name: "WEEKLY EXTERNAL"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("case-variant duplicate err = %v, want ErrConflict", err)
	}
	// The same name in another project is a different profile.
	if _, err := s.Create(ctx, other, CreateInput{Name: "Weekly external"}); err != nil {
		t.Fatalf("same name in another project: %v", err)
	}
}

func TestUpdateReplacesScannerBindings(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	nmap, nuclei, zap := scanner(t), scanner(t), scanner(t)

	created, err := s.Create(ctx, project, CreateInput{
		Name: "Evolving", Description: "keep me", TimeoutSeconds: 600,
		TargetSelection: []string{"example.com"},
		ReportPrefs:     json.RawMessage(`{"format":"html"}`),
		Scanners:        []ScannerBinding{{ScannerID: nmap, Config: json.RawMessage(`{"a":1}`), SortOrder: 3}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	originalUpdated := created.UpdatedAt

	// A nil scanner list leaves the bindings alone but may still patch fields.
	renamed, err := s.Update(ctx, created.ID, UpdateInput{Name: strPtr("Evolving v2")})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.Name != "Evolving v2" {
		t.Fatalf("name = %q", renamed.Name)
	}
	if len(renamed.Scanners) != 1 || renamed.Scanners[0].ScannerID != nmap {
		t.Fatalf("nil scanner list changed the bindings: %+v", renamed.Scanners)
	}
	if renamed.Description != "keep me" || renamed.TimeoutSeconds != 600 {
		t.Fatalf("untouched fields were reset: %+v", renamed)
	}
	if strings.Join(renamed.TargetSelection, ",") != "example.com" {
		t.Fatalf("target_selection reset: %v", renamed.TargetSelection)
	}
	if !strings.Contains(string(renamed.ReportPrefs), "html") {
		t.Fatalf("report_prefs reset: %s", renamed.ReportPrefs)
	}
	if !renamed.UpdatedAt.After(originalUpdated) && !renamed.UpdatedAt.Equal(originalUpdated) {
		t.Fatalf("updated_at did not advance: %v -> %v", originalUpdated, renamed.UpdatedAt)
	}

	// Replace-all: the new list is the whole scanner set, in the given order.
	replaced, err := s.Update(ctx, created.ID, UpdateInput{Scanners: &[]ScannerBinding{
		{ScannerID: zap, Config: json.RawMessage(`{"proxies":1}`), SortOrder: 0},
		{ScannerID: nuclei, SortOrder: 1},
	}})
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if len(replaced.Scanners) != 2 {
		t.Fatalf("scanners = %+v, want 2", replaced.Scanners)
	}
	if replaced.Scanners[0].ScannerID != zap || replaced.Scanners[1].ScannerID != nuclei {
		t.Fatalf("replace did not honour the new set: %+v", replaced.Scanners)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scan_profile_scanners WHERE profile_id = $1`, created.ID); n != 2 {
		t.Fatalf("binding rows = %d, want 2 (stale rows survived)", n)
	}
	if n := itest.Count(t,
		`SELECT count(*) FROM scan_profile_scanners WHERE profile_id = $1 AND scanner_id = $2`, created.ID, nmap); n != 0 {
		t.Fatalf("the dropped scanner binding survived")
	}
	// An explicit empty list clears the recipe.
	cleared, err := s.Update(ctx, created.ID, UpdateInput{Scanners: &[]ScannerBinding{}})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(cleared.Scanners) != 0 {
		t.Fatalf("scanners = %+v, want none", cleared.Scanners)
	}

	// Patching the remaining fields independently.
	prefs := json.RawMessage(`{"format":"csv"}`)
	timeout := 90
	targets := []string{"shop.example.com", "shop.example.com", " "}
	excluded := []string{"10.0.0.0/8"}
	patched, err := s.Update(ctx, created.ID, UpdateInput{
		Description: strPtr("patched"), TimeoutSeconds: &timeout,
		TargetSelection: &targets, ExcludedTargets: &excluded, ReportPrefs: &prefs,
	})
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if patched.Description != "patched" || patched.TimeoutSeconds != timeout {
		t.Fatalf("patch ignored fields: %+v", patched)
	}
	if strings.Join(patched.TargetSelection, "|") != "shop.example.com" {
		t.Fatalf("target_selection = %v", patched.TargetSelection)
	}
	if strings.Join(patched.ExcludedTargets, "|") != "10.0.0.0/8" {
		t.Fatalf("excluded_targets = %v", patched.ExcludedTargets)
	}
	if !strings.Contains(string(patched.ReportPrefs), "csv") {
		t.Fatalf("report_prefs = %s", patched.ReportPrefs)
	}
}

// TestUpdateIsAtomicOnInvalidScanners is the reason the binding replacement
// lives in one transaction: a rejected scanner list must leave the profile
// exactly as it was, name included.
func TestUpdateIsAtomicOnInvalidScanners(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	good := scanner(t)

	created, err := s.Create(ctx, project, CreateInput{
		Name: "Atomic", Scanners: []ScannerBinding{{ScannerID: good}}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = s.Update(ctx, created.ID, UpdateInput{
		Name:     strPtr("Renamed while failing"),
		Scanners: &[]ScannerBinding{{ScannerID: uuid.New()}},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Atomic" {
		t.Fatalf("name changed despite the rollback: %q", got.Name)
	}
	if len(got.Scanners) != 1 || got.Scanners[0].ScannerID != good {
		t.Fatalf("bindings changed despite the rollback: %+v", got.Scanners)
	}
}

func TestUpdateAndDeleteErrors(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	other := itest.NewProject(t, "")
	good := scanner(t)

	a, err := s.Create(ctx, project, CreateInput{Name: "Alpha", Scanners: []ScannerBinding{{ScannerID: good}}})
	if err != nil {
		t.Fatalf("create alpha: %v", err)
	}
	if _, err := s.Create(ctx, other, CreateInput{Name: "Beta"}); err != nil {
		t.Fatalf("create beta: %v", err)
	}

	// Renaming onto a name that is taken in the same project conflicts...
	if _, err := s.Update(ctx, a.ID, UpdateInput{Name: strPtr("Alpha ")}); err != nil {
		t.Fatalf("no-op rename should succeed: %v", err)
	}
	// ...but a name owned by another project is free.
	if _, err := s.Update(ctx, a.ID, UpdateInput{Name: strPtr("beta")}); err != nil {
		t.Fatalf("rename across projects: %v", err)
	}
	// Renaming so as to collide with itself is not a conflict.
	if _, err := s.Update(ctx, a.ID, UpdateInput{Name: strPtr("BETA")}); err != nil {
		t.Fatalf("self rename: %v", err)
	}

	if _, err := s.Update(ctx, a.ID, UpdateInput{TimeoutSeconds: intPtr(0)}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("explicit zero timeout err = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Update(ctx, a.ID, UpdateInput{Name: strPtr("")}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("blank rename err = %v, want ErrInvalidInput", err)
	}
	brokenPrefs := json.RawMessage(`nope`)
	if _, err := s.Update(ctx, a.ID, UpdateInput{ReportPrefs: &brokenPrefs}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("broken report_prefs err = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Update(ctx, uuid.New(), UpdateInput{Name: strPtr("ghost")}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing err = %v, want ErrNotFound", err)
	}

	if err := s.Delete(ctx, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scan_profile_scanners WHERE profile_id = $1`, a.ID); n != 0 {
		t.Fatal("bindings survived the profile delete")
	}
	if err := s.Delete(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete err = %v, want ErrNotFound", err)
	}
	if _, err := s.Get(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete err = %v, want ErrNotFound", err)
	}
}

func TestListProfiles(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	other := itest.NewProject(t, "")
	nmap, nuclei := scanner(t), scanner(t)

	for _, in := range []CreateInput{
		{Name: "alpha external", Description: "perimeter", Scanners: []ScannerBinding{{ScannerID: nmap}, {ScannerID: nuclei}}},
		{Name: "Beta internal", Description: "internal net", TimeoutSeconds: 300},
		{Name: "gamma web", Description: "perimeter apps", TimeoutSeconds: 60},
	} {
		if _, err := s.Create(ctx, project, in); err != nil {
			t.Fatalf("create %s: %v", in.Name, err)
		}
	}
	if _, err := s.Create(ctx, other, CreateInput{Name: "foreign"}); err != nil {
		t.Fatalf("create foreign: %v", err)
	}

	all, total, err := s.List(ctx, project, ListFilters{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 || total != 3 {
		t.Fatalf("list = %d/%d, want 3/3", len(all), total)
	}
	// The default order is by name, case-insensitively.
	if all[0].Name != "alpha external" || all[2].Name != "gamma web" {
		t.Fatalf("default order = [%q %q %q]", all[0].Name, all[1].Name, all[2].Name)
	}
	// Every list entry carries its bindings without an extra round trip per row.
	if len(all[0].Scanners) != 2 {
		t.Fatalf("alpha bindings = %+v", all[0].Scanners)
	}
	if all[1].Scanners == nil {
		t.Fatal("a profile without bindings must serialise as an empty list, not nil")
	}

	byQuery, total, err := s.List(ctx, project, ListFilters{Query: "perimeter"})
	if err != nil || len(byQuery) != 2 || total != 2 {
		t.Fatalf("query filter = %d/%d (%v)", len(byQuery), total, err)
	}
	byName, _, err := s.List(ctx, project, ListFilters{Query: "GAMMA"})
	if err != nil || len(byName) != 1 {
		t.Fatalf("case-insensitive name query = %d (%v)", len(byName), err)
	}
	if items, _, err := s.List(ctx, project, ListFilters{Query: "100%"}); err != nil || len(items) != 0 {
		t.Fatalf("LIKE wildcard leaked: %d (%v)", len(items), err)
	}
	byTimeout, _, err := s.List(ctx, project, ListFilters{Sort: "timeout_seconds"})
	if err != nil {
		t.Fatalf("timeout sort: %v", err)
	}
	if byTimeout[0].TimeoutSeconds != 60 || byTimeout[2].TimeoutSeconds != defaultTimeout {
		t.Fatalf("timeout order = [%d %d %d]", byTimeout[0].TimeoutSeconds, byTimeout[1].TimeoutSeconds, byTimeout[2].TimeoutSeconds)
	}
	reversed, _, err := s.List(ctx, project, ListFilters{Sort: "name", Desc: true})
	if err != nil || reversed[0].Name != "gamma web" {
		t.Fatalf("descending name order = %q (%v)", reversed[0].Name, err)
	}
	if _, _, err := s.List(ctx, project, ListFilters{Sort: "drop_tables"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad sort err = %v", err)
	}
	page, total, err := s.List(ctx, project, ListFilters{Limit: 2, Sort: "name"})
	if err != nil || len(page) != 2 || total != 3 {
		t.Fatalf("page = %d/%d (%v)", len(page), total, err)
	}
	rest, total, err := s.List(ctx, project, ListFilters{Limit: 2, Offset: 2, Sort: "name"})
	if err != nil || len(rest) != 1 || total != 3 {
		t.Fatalf("second page = %d/%d (%v)", len(rest), total, err)
	}
	// Another project's profiles never leak into the list.
	foreign, _, err := s.List(ctx, other, ListFilters{})
	if err != nil || len(foreign) != 1 || foreign[0].Name != "foreign" {
		t.Fatalf("cross-project list = %+v (%v)", foreign, err)
	}
	if _, _, err := s.List(ctx, uuid.New(), ListFilters{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown project err = %v, want ErrNotFound", err)
	}
}

func TestProfilesHTTPSurface(t *testing.T) {
	s := newService()
	r := chi.NewRouter()
	s.Register(r)
	project := itest.NewProject(t, "")
	nmap := scanner(t)

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
	rec := do("POST", base+"/profiles", `{"name":"HTTP profile","description":"created over HTTP",
		"timeout_seconds":120,"target_selection":["example.com"],
		"report_prefs":{"format":"pdf"},
		"scanners":[{"scanner_id":"`+nmap.String()+`","config":{"ports":"top-1000"},"sort_order":0}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body = %s", rec.Code, rec.Body)
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	profileID, _ := created["id"].(string)
	if profileID == "" {
		t.Fatalf("no id in %s", rec.Body)
	}
	if v, ok := created["timeout_seconds"].(float64); !ok || v != 120 {
		t.Fatalf("timeout_seconds = %v", created["timeout_seconds"])
	}
	scannersField, ok := created["scanners"].([]any)
	if !ok || len(scannersField) != 1 {
		t.Fatalf("scanners = %v", created["scanners"])
	}
	first := scannersField[0].(map[string]any)
	if first["scanner"] == "" || first["scanner_id"] != nmap.String() {
		t.Fatalf("binding = %v", first)
	}

	// Duplicate name, and the case-insensitive variant.
	if rec := do("POST", base+"/profiles", `{"name":"http profile"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate name code = %d, want 409 body = %s", rec.Code, rec.Body)
	}
	// Blank name, unknown scanner, disabled scanner.
	if rec := do("POST", base+"/profiles", `{"name":"  "}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("blank name code = %d, want 400", rec.Code)
	}
	if rec := do("POST", base+"/profiles", `{"name":"ghost","scanners":[{"scanner_id":"`+uuid.NewString()+`"}]}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown scanner code = %d, want 404", rec.Code)
	}
	if rec := do("POST", base+"/profiles", `{"name":"bad cfg","scanners":[{"scanner_id":"`+nmap.String()+`","config":[1,2]}]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad config code = %d, want 400", rec.Code)
	}
	if rec := do("POST", base+"/profiles", `{"name":"bad timeout","timeout_seconds":999999}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad timeout code = %d, want 400", rec.Code)
	}
	if rec := do("POST", base+"/profiles", `{"name":"unknown field","bogus":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field code = %d, want 400", rec.Code)
	}
	if rec := do("POST", "/projects/"+uuid.NewString()+"/profiles", `{"name":"orphan"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown project code = %d, want 404", rec.Code)
	}
	if rec := do("POST", base+"/profiles", `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body code = %d, want 400", rec.Code)
	}

	// GET one, GET list.
	if rec := do("GET", "/profiles/"+profileID, ""); rec.Code != http.StatusOK {
		t.Fatalf("get code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"scanners"`) {
		t.Fatalf("get body lacks scanners: %s", rec.Body)
	}
	if rec := do("GET", "/profiles/"+uuid.NewString(), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing get code = %d", rec.Code)
	}
	if rec := do("GET", "/profiles/not-a-uuid", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad uuid code = %d, want 400", rec.Code)
	}
	if rec := do("GET", base+"/profiles?q=HTTP&limit=10", ""); rec.Code != http.StatusOK {
		t.Fatalf("list code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("list body = %s", rec.Body)
	}
	// A profile that binds nothing still reports an empty list, never null.
	if rec := do("POST", base+"/profiles", `{"name":"draft, no scanners"}`); rec.Code != http.StatusCreated {
		t.Fatalf("draft create code = %d body = %s", rec.Code, rec.Body)
	} else if !strings.Contains(rec.Body.String(), `"scanners":[]`) {
		t.Fatalf("draft body = %s, want scanners:[]", rec.Body)
	}
	if rec := do("GET", base+"/profiles?sort=bogus", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad sort code = %d, want 400", rec.Code)
	}

	// PUT: replace the scanner set and rename in one call.
	if rec := do("PUT", "/profiles/"+profileID,
		`{"name":"HTTP profile v2","scanners":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("update code = %d body = %s", rec.Code, rec.Body)
	} else {
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode update: %v", err)
		}
		if out["name"] != "HTTP profile v2" {
			t.Fatalf("rename ignored: %v", out["name"])
		}
		if list, ok := out["scanners"].([]any); !ok || len(list) != 0 {
			t.Fatalf("scanner list not cleared: %v", out["scanners"])
		}
		if out["description"] != "created over HTTP" {
			t.Fatalf("untouched description changed: %v", out["description"])
		}
	}
	if rec := do("PUT", "/profiles/"+profileID, `{"timeout_seconds":-1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad update code = %d, want 400", rec.Code)
	}
	if rec := do("PUT", "/profiles/"+uuid.NewString(), `{"name":"ghost"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("missing update code = %d, want 404", rec.Code)
	}

	// DELETE, then the cascade and the 404.
	if rec := do("DELETE", "/profiles/"+profileID, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete code = %d", rec.Code)
	}
	if rec := do("DELETE", "/profiles/"+profileID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("double delete code = %d, want 404", rec.Code)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scan_profile_scanners WHERE profile_id = $1`, profileID); n != 0 {
		t.Fatalf("bindings survived the HTTP delete")
	}
}

// TestProfileHistorySurvivesDelete pins the guarantee that lets operators
// clean up recipes: scan sessions keep their own target and scanner lists, so
// deleting a profile must never rewrite assessment history.
func TestProfileHistorySurvivesDelete(t *testing.T) {
	ctx := context.Background()
	s := newService()
	project := itest.NewProject(t, "")
	profile, err := s.Create(ctx, project, CreateInput{Name: "Ephemeral"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	session := itest.NewScanSession(t, project)
	itest.MustExec(t, `UPDATE scan_sessions SET profile_id = $2 WHERE id = $1`, session, profile.ID)

	if err := s.Delete(ctx, profile.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var profileID *string
	if err := itest.DB().QueryRow(ctx, `SELECT profile_id::text FROM scan_sessions WHERE id = $1`, session).Scan(&profileID); err != nil {
		t.Fatalf("read session: %v", err)
	}
	if profileID != nil {
		t.Fatalf("profile_id = %v, want it set to null", *profileID)
	}
	if n := itest.Count(t, `SELECT count(*) FROM scan_sessions WHERE id = $1`, session); n != 1 {
		t.Fatal("deleting a profile deleted a scan session")
	}
}

// TestViewAlwaysExposesTheScannerList pins the JSON contract: the list is
// present even when the profile binds nothing, and it is the service's list.
func TestViewAlwaysExposesTheScannerList(t *testing.T) {
	empty := viewOf(&models.ScanProfile{ID: uuid.New(), Name: "empty"})
	raw, err := json.Marshal(empty)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"scanners":[]`) {
		t.Fatalf("empty profile JSON = %s, want scanners:[]", raw)
	}

	full := viewOf(&models.ScanProfile{
		ID: uuid.New(), Name: "full",
		Scanners: []models.ProfileScanner{{Scanner: "nmap", ScannerID: uuid.New()}},
	})
	raw, _ = json.Marshal(full)
	if !strings.Contains(string(raw), `"scanners":[{"id"`) || !strings.Contains(string(raw), `"scanner":"nmap"`) {
		t.Fatalf("populated profile JSON = %s", raw)
	}
	// The embedded model still supplies the other keys.
	for _, key := range []string{`"target_selection"`, `"excluded_targets"`, `"report_prefs"`, `"timeout_seconds"`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("view JSON lost %s: %s", key, raw)
		}
	}
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }
