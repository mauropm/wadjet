package projects

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

func TestProjectCRUDLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newService(t)

	name := uniqueName(t, "lifecycle")
	p := mustCreate(t, s, name)
	if p.Status != models.ProjectStatusActive {
		t.Fatalf("status = %q, want active", p.Status)
	}
	if p.ID == uuid.Nil {
		t.Fatal("expected generated id")
	}
	if p.LastActivity != nil {
		t.Fatal("last_activity_at should start nil")
	}

	got, err := s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != name {
		t.Fatalf("name = %q, want %q", got.Name, name)
	}

	// Update: name, description, tags and settings.
	newDesc := "payment gateway assessment"
	tags := []string{"  web ", "api", "", "WEB", "external"}
	newSettings := json.RawMessage(`{"report_prefs":{"include_evidence":true}}`)
	updated, err := s.Update(ctx, p.ID, UpdateInput{Description: &newDesc, Tags: &tags, Settings: newSettings})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Description != newDesc {
		t.Fatalf("description = %q", updated.Description)
	}
	if len(updated.Tags) != 3 {
		t.Fatalf("tags = %#v, want blanks dropped and case-insensitive dedup", updated.Tags)
	}
	if !strings.Contains(string(updated.Settings), "include_evidence") {
		t.Fatalf("settings not persisted: %s", updated.Settings)
	}

	// Partial update leaves other fields untouched.
	only := "renamed"
	if _, err := s.Update(ctx, p.ID, UpdateInput{Name: &only}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	after, err := s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get after rename: %v", err)
	}
	if after.Name != only || after.Description != newDesc || len(after.Tags) != 3 {
		t.Fatalf("partial update clobbered fields: %+v", after)
	}

	// Invalid input is rejected.
	if _, err := s.Update(ctx, p.ID, UpdateInput{Status: strPtr("bogus")}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("update status=bogus err = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Update(ctx, p.ID, UpdateInput{Settings: json.RawMessage(`[1,2]`)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("settings array err = %v, want ErrInvalidInput", err)
	}
	if _, err := s.Create(ctx, CreateInput{Name: "   "}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("blank name err = %v, want ErrInvalidInput", err)
	}

	// Unknown project.
	if _, err := s.Get(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing err = %v, want ErrNotFound", err)
	}

	// TouchActivity stamps last_activity_at.
	if err := s.TouchActivity(ctx, p.ID); err != nil {
		t.Fatalf("touch: %v", err)
	}
	touched, err := s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get after touch: %v", err)
	}
	if touched.LastActivity == nil {
		t.Fatal("TouchActivity did not stamp last_activity_at")
	}
}

func TestProjectRetentionAndDelete(t *testing.T) {
	ctx := context.Background()
	s := newService(t)

	p := mustCreate(t, s, uniqueName(t, "retention"))

	// Active project: delete always refused, even with force.
	if err := s.Delete(ctx, p.ID, false); !errors.Is(err, ErrNotArchived) {
		t.Fatalf("delete active err = %v, want ErrNotArchived", err)
	}
	if err := s.Delete(ctx, p.ID, true); !errors.Is(err, ErrNotArchived) {
		t.Fatalf("delete active force err = %v, want ErrNotArchived", err)
	}

	// Archive, then retention policy blocks a non-forced delete.
	archived, err := s.Archive(ctx, p.ID)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if archived.Status != models.ProjectStatusArchived {
		t.Fatalf("status = %q, want archived", archived.Status)
	}
	if err := s.Delete(ctx, p.ID, false); !errors.Is(err, ErrRetentionPolicy) {
		t.Fatalf("delete archived err = %v, want ErrRetentionPolicy", err)
	}
	if queryRowInt(t, `SELECT count(*) FROM projects WHERE id = $1`, p.ID) != 1 {
		t.Fatal("archived project was deleted without force")
	}

	// Archived + force actually removes the row.
	if err := s.Delete(ctx, p.ID, true); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if queryRowInt(t, `SELECT count(*) FROM projects WHERE id = $1`, p.ID) != 0 {
		t.Fatal("project still present after forced delete")
	}
	if err := s.Delete(ctx, p.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing err = %v, want ErrNotFound", err)
	}
}

func TestProjectListFilters(t *testing.T) {
	ctx := context.Background()
	s := newService(t)

	base := uniqueName(t, "list")
	a := mustCreate(t, s, base+" alpha payment")
	if _, err := s.Update(ctx, a.ID, UpdateInput{
		Description: strPtr("card holder data environment"),
		Tags:        &[]string{"pci", "prod"},
	}); err != nil {
		t.Fatalf("update a: %v", err)
	}
	b := mustCreate(t, s, base+" beta mail")
	if _, err := s.Archive(ctx, b.ID); err != nil {
		t.Fatalf("archive b: %v", err)
	}
	mustCreate(t, s, base+" gamma docs")

	find := func(f ListFilters) []models.Project {
		t.Helper()
		items, _, err := s.List(ctx, f)
		if err != nil {
			t.Fatalf("list %+v: %v", f, err)
		}
		return items
	}

	all := find(ListFilters{Query: base, Sort: "name", Descending: false})
	if len(all) != 3 {
		t.Fatalf("unfiltered list = %d, want 3", len(all))
	}
	byName := find(ListFilters{Query: "PAYMENT", Sort: "name"})
	if len(byName) != 1 || byName[0].ID != a.ID {
		t.Fatalf("q=PAYMENT matched %d projects", len(byName))
	}
	byDesc := find(ListFilters{Query: "card holder"})
	if len(byDesc) != 1 || byDesc[0].ID != a.ID {
		t.Fatalf("q by description matched %d", len(byDesc))
	}
	byTag := find(ListFilters{Query: "pci"})
	if len(byTag) != 1 || byTag[0].ID != a.ID {
		t.Fatalf("q by tag matched %d", len(byTag))
	}
	// ILIKE wildcards in user input must be treated literally.
	if got := find(ListFilters{Query: "%"}); len(got) != 0 {
		t.Fatalf("query '%%' matched %d projects, want 0 (wildcard escaped)", len(got))
	}
	if got := find(ListFilters{Query: base, Status: models.ProjectStatusArchived}); len(got) != 1 || got[0].ID != b.ID {
		t.Fatalf("status filter = %d, want only the archived project", len(got))
	}
	if _, _, err := s.List(ctx, ListFilters{Status: "nope"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad status err = %v", err)
	}
	if _, _, err := s.List(ctx, ListFilters{Sort: "drop_tables"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad sort err = %v", err)
	}

	// Pagination + total.
	page, total, err := s.List(ctx, ListFilters{Query: base, Limit: 2, Offset: 0, Sort: "name"})
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if total != 3 || len(page) != 2 {
		t.Fatalf("pagination total=%d len=%d, want 3/2", total, len(page))
	}
	page2, _, err := s.List(ctx, ListFilters{Query: base, Limit: 2, Offset: 2, Sort: "name"})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 1 || page2[0].ID == page[0].ID || page2[0].ID == page[1].ID {
		t.Fatalf("offset paging overlapped: %+v", page2)
	}
}

func TestProjectHTTPSurface(t *testing.T) {
	s := NewService(itest.DB(), nil)
	r := chi.NewRouter()
	s.Register(r)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	name := uniqueName(t, "http")
	rec := do("POST", "/projects", `{"name":"`+name+`","description":"d","tags":["a"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body=%s", rec.Code, rec.Body)
	}
	var created models.Project
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = itest.DB().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, created.ID)
	})

	if rec := do("GET", "/projects/"+created.ID.String(), ""); rec.Code != http.StatusOK {
		t.Fatalf("get code = %d", rec.Code)
	}
	if rec := do("PUT", "/projects/"+created.ID.String(), `{"description":"updated"}`); rec.Code != http.StatusOK {
		t.Fatalf("put code = %d body=%s", rec.Code, rec.Body)
	}
	if rec := do("GET", "/projects?q="+name, ""); rec.Code != http.StatusOK {
		t.Fatalf("list code = %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), `"total":1`) {
		t.Fatalf("list body = %s", rec.Body)
	}
	if rec := do("POST", "/projects", `{"name":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("blank name code = %d", rec.Code)
	}
	if rec := do("POST", "/projects", `{"name":"x","unknown":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field code = %d, want 400 (DisallowUnknownFields)", rec.Code)
	}
	if rec := do("GET", "/projects/"+uuid.NewString(), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing code = %d", rec.Code)
	}
	if rec := do("GET", "/projects/not-a-uuid", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad uuid code = %d", rec.Code)
	}
	if rec := do("DELETE", "/projects/"+created.ID.String(), ""); rec.Code != http.StatusConflict {
		t.Fatalf("delete active code = %d, want 409", rec.Code)
	}
	if rec := do("POST", "/projects/"+created.ID.String()+"/archive", ""); rec.Code != http.StatusOK {
		t.Fatalf("archive code = %d", rec.Code)
	}
	if rec := do("DELETE", "/projects/"+created.ID.String(), ""); rec.Code != http.StatusConflict {
		t.Fatalf("delete archived without force code = %d, want 409", rec.Code)
	}
	if rec := do("DELETE", "/projects/"+created.ID.String()+"?force=true", ""); rec.Code != http.StatusOK {
		t.Fatalf("forced delete code = %d", rec.Code)
	}
	if queryRowInt(t, `SELECT count(*) FROM projects WHERE id = $1`, created.ID) != 0 {
		t.Fatal("project survived forced delete")
	}
}

func strPtr(s string) *string { return &s }
