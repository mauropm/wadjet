package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/auth"
	"github.com/mauropm/wadjet/internal/config"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/models"
)

const devBypassTestDB = "postgres://wadjet:***@127.0.0.1:5432/wadjet?sslmode=disable"

func newBypassServer(t *testing.T, env, adminEmail string, createAdmin bool) *Server {
	t.Helper()
	db, err := database.Open(context.Background(), devBypassTestDB)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	require.NoError(t, database.Migrate(context.Background(), db))
	authSvc := auth.NewService(db, "test-secret")
	// With createAdmin, the impersonated principal is a real users row so
	// created_by foreign keys stay valid. Multiple cases share the email:
	// a taken email from an earlier invocation is fine (row is reused).
	if createAdmin {
		if _, err := authSvc.CreateUser(context.Background(), adminEmail, "Dev Admin", "devpassword123", "admin"); err != nil && err != auth.ErrEmailTaken {
			require.NoError(t, err)
		}
	}
	return &Server{cfg: &config.Config{Env: env, AdminEmail: adminEmail}, db: db, auth: authSvc}
}

func serveAuthed(s *Server) (*models.User, int) {
	var seen *models.User
	h := s.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil))
	return seen, rec.Code
}

// The dev no-login bypass must be a strict double gate: WADJET_DEV_NO_LOGIN=1
// AND development mode. Any other combination stays a hard 401.
func TestDevNoLoginBypassGate(t *testing.T) {
	admin := "devbypass-" + uuid.New().String()[:8] + "@wadjet.local"

	// Flag unset (empty is not "1") → 401 even in development.
	s := newBypassServer(t, "development", admin, true)
	t.Setenv("WADJET_DEV_NO_LOGIN", "")
	if u, code := serveAuthed(s); code != http.StatusUnauthorized || u != nil {
		t.Fatalf("no flag, development: got code=%d user=%v, want 401/nil", code, u)
	}

	// Flag set but production → 401 (never impersonate in prod).
	s = newBypassServer(t, "production", admin, true)
	t.Setenv("WADJET_DEV_NO_LOGIN", "1")
	if u, code := serveAuthed(s); code != http.StatusUnauthorized || u != nil {
		t.Fatalf("flag set, production: got code=%d user=%v, want 401/nil", code, u)
	}

	// SEC-DEV-1: the gate is the allowlist "exactly development", not the
	// fail-open != "production". Every ambiguous env value + flag → 401.
	for _, env := range []string{"Production", "PROD", "prod", "productio", ""} {
		s = newBypassServer(t, env, admin, true)
		t.Setenv("WADJET_DEV_NO_LOGIN", "1")
		if u, code := serveAuthed(s); code != http.StatusUnauthorized || u != nil {
			t.Fatalf("flag set, env=%q: got code=%d user=%v, want 401/nil", env, code, u)
		}
	}
	// Exact match is case-insensitive/trim-tolerant though.
	s = newBypassServer(t, " Development ", admin, true)
	t.Setenv("WADJET_DEV_NO_LOGIN", "1")
	if _, code := serveAuthed(s); code != http.StatusOK {
		t.Fatalf("flag set, env=' Development ': got code=%d, want 200", code)
	}

	// Flag set + development → 200 as the admin principal.
	s = newBypassServer(t, "development", admin, true)
	t.Setenv("WADJET_DEV_NO_LOGIN", "1")
	u, code := serveAuthed(s)
	assert.Equal(t, http.StatusOK, code)
	if assert.NotNil(t, u) {
		assert.Equal(t, "admin", u.Role)
		assert.Equal(t, admin, u.Email)
	}

	// Unknown admin email (no row) → fail closed with 401, not a panic.
	s = newBypassServer(t, "development", "missing-"+uuid.New().String()[:8]+"@wadjet.local", false)
	t.Setenv("WADJET_DEV_NO_LOGIN", "1")
	if u, code := serveAuthed(s); code != http.StatusUnauthorized || u != nil {
		t.Fatalf("missing admin row: got code=%d user=%v, want 401/nil", code, u)
	}
}

// SEC-DEV-5: the impersonated principal must be resolved per request, never
// cached — demoting the admin row takes effect on the very next request
// without a process restart.
func TestDevNoLoginRevalidatesPrincipal(t *testing.T) {
	admin := "devreval-" + uuid.New().String()[:8] + "@wadjet.local"
	s := newBypassServer(t, "development", admin, true)
	t.Setenv("WADJET_DEV_NO_LOGIN", "1")

	if _, code := serveAuthed(s); code != http.StatusOK {
		t.Fatalf("baseline: got code=%d, want 200", code)
	}
	_, err := s.db.Exec(context.Background(), `UPDATE users SET role = 'user' WHERE email = $1`, admin)
	require.NoError(t, err)
	if u, code := serveAuthed(s); code != http.StatusUnauthorized || u != nil {
		t.Fatalf("after demotion: got code=%d user=%v, want 401/nil (cached principal!)", code, u)
	}
	_, err = s.db.Exec(context.Background(), `UPDATE users SET role = 'admin' WHERE email = $1`, admin)
	require.NoError(t, err)
	if _, code := serveAuthed(s); code != http.StatusOK {
		t.Fatalf("after re-promotion: got code=%d, want 200", code)
	}
}
