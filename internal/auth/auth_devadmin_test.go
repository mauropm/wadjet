package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/database"
)

const authTestDB = "postgres://wadjet:***@127.0.0.1:5432/wadjet?sslmode=disable"

func newAuthSvc(t *testing.T) *Service {
	t.Helper()
	db, err := database.Open(context.Background(), authTestDB)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	require.NoError(t, database.Migrate(context.Background(), db))
	return NewService(db, "test-secret")
}

// SEC-DEV-2 / VER-SDEV-2a: EnsureUserByEmail stores the *given* password —
// boot passes a random nonce, never the shipped default — and an existing
// account's credential is never overwritten.
func TestEnsureUserByEmail(t *testing.T) {
	ctx := context.Background()
	svc := newAuthSvc(t)

	email := "ensure-" + uuid.New().String()[:8] + "@wadjet.local"
	const bootPass = "nonce-v-alues-are-random-64-hex"

	require.NoError(t, svc.EnsureUserByEmail(ctx, email, "Administrator", bootPass, "admin"))

	// The row exists with the supplied credential and admin role.
	u, _, err := svc.Login(ctx, email, bootPass)
	require.NoError(t, err)
	require.Equal(t, "admin", u.Role)

	// Idempotent: a second call with a DIFFERENT password must not
	// clobber (or duplicate) the existing credential.
	require.NoError(t, svc.EnsureUserByEmail(ctx, email, "Administrator", "another-password-123", "admin"))
	_, _, err = svc.Login(ctx, email, bootPass)
	require.NoError(t, err, "original password must survive a repeat EnsureUserByEmail")
	_, _, err = svc.Login(ctx, email, "another-password-123")
	require.Error(t, err, "repeat call must not replace the password")

	// Email is matched case-insensitively/trimmed like Login/CreateUser.
	require.NoError(t, svc.EnsureUserByEmail(ctx, "  "+upper(email)+"  ", "Administrator", "whatever-1234567", "admin"))
	_, _, err = svc.Login(ctx, email, bootPass)
	require.NoError(t, err, "case/space variants must resolve to the same row")
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}
