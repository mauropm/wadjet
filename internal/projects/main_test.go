package projects

import (
	"context"
	"testing"

	"github.com/mauropm/wadjet/internal/assets/itest"
	"github.com/mauropm/wadjet/internal/models"
)

// TestMain opens one isolated database and applies the schema once per run.
func TestMain(m *testing.M) { itest.Main(m, "projects") }

func newService(t *testing.T) *Service {
	t.Helper()
	return NewService(itest.DB(), nil)
}

func uniqueName(t *testing.T, prefix string) string { return itest.UniqueName(t, prefix) }

func queryRowInt(t *testing.T, sql string, args ...any) int {
	t.Helper()
	return itest.Count(t, sql, args...)
}

// mustCreate creates a project through the service and removes it, with all
// cascading rows, when the test ends.
func mustCreate(t *testing.T, s *Service, name string) *models.Project {
	t.Helper()
	if name == "" {
		name = uniqueName(t, "proj")
	}
	p, err := s.Create(context.Background(), CreateInput{Name: name})
	if err != nil {
		t.Fatalf("create project %q: %v", name, err)
	}
	itest.CleanupProject(t, p.ID)
	return p
}
