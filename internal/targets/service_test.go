package targets

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

func TestAuthorizeAgainstDatabase(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")

	add := func(target, typ string, excluded bool) {
		t.Helper()
		if _, err := s.Create(ctx, project, target, typ, "seed", excluded); err != nil {
			t.Fatalf("create %q: %v", target, err)
		}
	}
	add("10.0.0.0/24", "auto", false)
	add("10.0.0.9", "auto", true)
	add("example.com", "auto", false)
	add("admin.example.com", "hostname", true)
	add("shop.example.com", "hostname", false)
	add("2001:db8::/32", "auto", false)

	// A row inserted behind the API that cannot be parsed must not authorise
	// anything and must not break the gate.
	itest.MustExec(t, `INSERT INTO project_targets (project_id, target, target_type) VALUES ($1,'$$$broken$$$','auto')`, project)

	cases := []struct {
		target string
		want   error
	}{
		{"10.0.0.5", nil},
		{"10.0.0.9", ErrExcluded},
		{"10.0.1.5", ErrNotAuthorized},
		{"https://shop.example.com/cart", nil},
		{"shop.example.com", nil},
		{"www.example.com", nil},
		{"admin.example.com", ErrExcluded},
		{"evil-example.com", ErrNotAuthorized},
		{"2001:db8::42", nil},
		{"2001:db9::1", ErrNotAuthorized},
		{"not-a-target!", ErrInvalidTarget},
	}
	for _, tc := range cases {
		err := s.Authorize(ctx, project, tc.target)
		if tc.want == nil && err != nil {
			t.Errorf("Authorize(%q) = %v, want nil", tc.target, err)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("Authorize(%q) = %v, want %v", tc.target, err, tc.want)
		}
	}

	// A project with no entries fails closed, including an unknown project id.
	empty := itest.NewProject(t, "")
	if err := s.Authorize(ctx, empty, "10.0.0.5"); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("empty project Authorize = %v, want ErrNotAuthorized", err)
	}
	if err := s.Authorize(ctx, uuid.New(), "10.0.0.5"); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("unknown project Authorize = %v, want ErrNotAuthorized", err)
	}

	// Bulk check reports the index of the first denial.
	idx, err := s.AuthorizeTargets(ctx, project, []string{"10.0.0.1", "10.0.0.2", "10.9.9.9"})
	if !errors.Is(err, ErrNotAuthorized) || idx != 2 {
		t.Errorf("AuthorizeTargets = idx %d, %v; want idx 2, ErrNotAuthorized", idx, err)
	}
	if idx, err := s.AuthorizeTargets(ctx, project, []string{"10.0.0.1", "10.0.0.2"}); err != nil || idx != 0 {
		t.Errorf("AuthorizeTargets in-scope = %d, %v; want 0, nil", idx, err)
	}
}

func TestTargetCreateValidation(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")

	if _, err := s.Create(ctx, project, "not a host", "", "", false); !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("garbage target err = %v, want ErrInvalidTarget", err)
	}
	if _, err := s.Create(ctx, project, "www.example.com", "ip", "", false); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("type mismatch err = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Create(ctx, project, "10.0.0.1", "sideways", "", false); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unknown type err = %v, want ErrInvalidInput", err)
	}

	created, err := s.Create(ctx, project, "10.10.0.0/24", "cidr", "lab range", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.TargetType != "cidr" || created.Note != "lab range" || created.Excluded {
		t.Fatalf("created = %+v", created)
	}
	if created.ID == uuid.Nil || created.ProjectID != project {
		t.Fatalf("created identity missing: %+v", created)
	}

	// Exact duplicate and case-variant duplicates are refused.
	if _, err := s.Create(ctx, project, "10.10.0.0/24", "cidr", "", false); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate err = %v, want ErrConflict", err)
	}
	if _, err := s.Create(ctx, project, "10.10.0.0/24", "auto", "", false); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate ignoring type err = %v, want ErrConflict", err)
	}
	if _, err := s.Create(ctx, project, "WWW.Example.com", "hostname", "", false); err != nil {
		t.Fatalf("first hostname: %v", err)
	}
	if _, err := s.Create(ctx, project, "www.example.COM", "hostname", "", false); !errors.Is(err, ErrConflict) {
		t.Errorf("case-variant duplicate err = %v, want ErrConflict", err)
	}
	// The same text may exist once as included and once as excluded.
	if _, err := s.Create(ctx, project, "10.10.0.0/24", "cidr", "deny lab", true); err != nil {
		t.Fatalf("same text excluded should be allowed: %v", err)
	}

	// Rows land in the database and are listed: the included CIDR, the
	// hostname and the same CIDR as an exclusion.
	items, total, err := s.List(ctx, project)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != len(items) || total != 3 {
		t.Fatalf("list = %d/%d, want 3/3", len(items), total)
	}
	if _, _, err := s.List(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("list unknown project err = %v, want ErrNotFound", err)
	}
}

func TestTargetUpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	s := NewService(itest.DB())
	project := itest.NewProject(t, "")

	created, err := s.Create(ctx, project, "192.0.2.10", "auto", "web node", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	note := "verified with the client"
	excluded := true
	updated, err := s.Update(ctx, created.ID, nil, nil, &note, &excluded)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Note != note || !updated.Excluded || updated.Target != created.Target {
		t.Fatalf("updated = %+v", updated)
	}
	// Flipping to excluded frees the included slot, so re-adding must work.
	if _, err := s.Create(ctx, project, "192.0.2.10", "auto", "", false); err != nil {
		t.Fatalf("re-add as included: %v", err)
	}

	bad := "!!!"
	if _, err := s.Update(ctx, created.ID, &bad, nil, nil, nil); !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("update to garbage err = %v, want ErrInvalidTarget", err)
	}
	if _, err := s.Update(ctx, uuid.New(), &note, nil, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing err = %v, want ErrNotFound", err)
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.Delete(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete err = %v, want ErrNotFound", err)
	}
	if n := itest.Count(t, `SELECT count(*) FROM project_targets WHERE id = $1`, created.ID); n != 0 {
		t.Fatal("row survived delete")
	}
}

func TestTargetsHTTPSurface(t *testing.T) {
	s := NewService(itest.DB())
	r := chi.NewRouter()
	s.Register(r)
	project := itest.NewProject(t, "")

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

	rec := do("POST", "/projects/"+project.String()+"/targets", `{"target":"10.20.30.0/24","target_type":"cidr","note":"lab"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body = %s", rec.Code, rec.Body)
	}
	var created models.ProjectTarget
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec := do("POST", "/projects/"+project.String()+"/targets", `{"target":"10.20.30.0/24"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate code = %d, want 409", rec.Code)
	}
	if rec := do("POST", "/projects/"+project.String()+"/targets", `{"target":"bad target"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid code = %d, want 400", rec.Code)
	}
	if rec := do("POST", "/projects/"+uuid.NewString()+"/targets", `{"target":"10.0.0.1"}`); rec.Code != http.StatusInternalServerError {
		t.Logf("note: create under missing project returned %d", rec.Code)
	}
	if rec := do("GET", "/projects/"+project.String()+"/targets", ""); rec.Code != http.StatusOK {
		t.Fatalf("list code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), "10.20.30.0/24") {
		t.Fatalf("list body = %s", rec.Body)
	}
	if rec := do("PUT", "/targets/"+created.ID.String(), `{"note":"edited"}`); rec.Code != http.StatusOK {
		t.Fatalf("update code = %d body = %s", rec.Code, rec.Body)
	}
	if rec := do("PUT", "/targets/"+uuid.NewString(), `{"note":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("update missing code = %d", rec.Code)
	}
	if rec := do("DELETE", "/targets/"+created.ID.String(), ""); rec.Code != http.StatusOK {
		t.Fatalf("delete code = %d", rec.Code)
	}
	if rec := do("DELETE", "/targets/"+created.ID.String(), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete twice code = %d", rec.Code)
	}
	if rec := do("GET", "/targets/"+created.ID.String()+"/targets", ""); rec.Code == http.StatusOK {
		t.Fatal("unexpected route matched")
	}
}
