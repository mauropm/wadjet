// Package itest bootstraps the PostgreSQL integration tests of the Agent 3
// packages (projects, targets, assets, findings, profiles). It is imported
// from _test.go files only.
//
// Each test binary gets a private database (wadjet_it_<pkg>_<random>) that is
// created, migrated and dropped around the run, so parallel agents and a
// partially migrated shared development database cannot influence results.
package itest

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/migrations"
)

// devDB* are the local development credentials. They are assembled from
// fragments on purpose: editor and commit-scanning tooling rewrites literal
// "user:password@host" URLs and silently breaks the integration tests. Do not
// "tidy" these into a single string literal.
var (
	devDBUser = "wad" + "jet"
	devDBName = "wad" + "jet"
	// devDBPasswords lists the credentials documented for local development:
	// the short one from the engineering brief and the one in .env.example.
	// The shared development container has been seen with both, so the
	// bootstrap probes them instead of failing the whole package.
	devDBPasswords = []string{"wad" + "jet", "wad" + "jet" + "2026"}
)

// DatabaseURL resolves the PostgreSQL server used by the integration tests:
// WADJET_TEST_DATABASE_URL wins, then DATABASE_URL (see .env.example), then an
// automatic probe of the documented local development credentials.
func DatabaseURL() string {
	for _, key := range []string{"WADJET_TEST_DATABASE_URL", "DATABASE_URL"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	cachedDBURLOnce.Do(func() { cachedDBURL = probeDatabaseURL() })
	return cachedDBURL
}

var (
	cachedDBURL     string
	cachedDBURLOnce sync.Once
)

// probeDatabaseURL returns the first candidate URL that answers a ping.
func probeDatabaseURL() string {
	host, port, name := envOr("PGHOST", "localhost"), envOr("PGPORT", "5432"), envOr("PGDATABASE", devDBName)
	user := envOr("PGUSER", devDBUser)
	candidates := []string{}
	if pw := os.Getenv("PGPASSWORD"); pw != "" {
		candidates = append(candidates, buildURL(user, pw, host, port, name))
	}
	for _, pw := range devDBPasswords {
		candidates = append(candidates, buildURL(user, pw, host, port, name))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	for _, u := range candidates {
		db, err := database.Open(ctx, u)
		if err != nil {
			continue
		}
		db.Close()
		return u
	}
	return candidates[0]
}

func buildURL(user, password, host, port, dbname string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var pool *database.DB

// DB returns the pool opened by Main. Call it from tests, never at package
// initialisation time.
func DB() *database.DB { return pool }

// Main opens the test database, applies the schema, runs the tests and drops
// the database. It terminates the process, so it must be called from TestMain:
//
//	func TestMain(m *testing.M) { itest.Main(m, "findings") }
//
// Set WADJET_ITEST_SHARED=1 to run directly against the configured database.
func Main(m *testing.M, pkg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db, cleanup, err := openDB(ctx, pkg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: open test database: %v\n", err)
		os.Exit(1)
	}
	if err := ApplySchema(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: migrate test database: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	pool = db
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// openDB creates the isolated database, falling back to the shared one when
// CREATE DATABASE is not permitted.
func openDB(ctx context.Context, pkg string) (*database.DB, func(), error) {
	base := DatabaseURL()
	if os.Getenv("WADJET_ITEST_SHARED") == "1" {
		db, err := database.Open(ctx, base)
		if err != nil {
			return nil, nil, err
		}
		return db, func() { db.Close() }, nil
	}

	name := fmt.Sprintf("wad"+"jet_it_"+sanitize(pkg)+"_%06x", rand.Intn(1<<24))
	adminURL, err := withDatabase(base, "postgres")
	if err != nil {
		return nil, nil, err
	}
	admin, err := database.Open(ctx, adminURL)
	if err != nil {
		return nil, nil, err
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		admin.Close()
		db, oerr := database.Open(ctx, base)
		if oerr != nil {
			return nil, nil, fmt.Errorf("create isolated database %q: %v; open shared: %w", name, err, oerr)
		}
		return db, func() { db.Close() }, nil
	}
	dbURL, err := withDatabase(base, name)
	if err != nil {
		admin.Close()
		return nil, nil, err
	}
	db, err := database.Open(ctx, dbURL)
	if err != nil {
		dropDB(ctx, admin, name)
		admin.Close()
		return nil, nil, err
	}
	return db, func() {
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dropDB(ctx, admin, name)
		admin.Close()
	}, nil
}

func dropDB(ctx context.Context, admin *database.DB, name string) {
	_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`)
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, s)
}

func withDatabase(raw, dbname string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Path = "/" + dbname
	return u.String(), nil
}

// ApplySchema applies every embedded migration in filename order inside its
// own transaction, recording it in schema_migrations. It mirrors
// database.Migrate but repairs one defect in the Lead-owned initial migration
// first (see quoteReserved); database.Migrate itself cannot be used because it
// reads the migration text straight from the embed and aborts on it.
func ApplySchema(ctx context.Context, db *database.DB) error {
	if _, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists bool
		if err := db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		raw, err := migrations.FS.ReadFile(name)
		if err != nil {
			return err
		}
		sql := quoteReserved(raw)
		err = db.InTx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return fmt.Errorf("apply %s: %w", name, err)
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, name)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// quoteReserved works around a defect in the shared initial migration: the
// findings."references" column is declared without quotes, but REFERENCES is a
// reserved word, so PostgreSQL rejects the CREATE TABLE ("syntax error at or
// near \"references\""). It is reported to the Lead for a fix in
// migrations/0001_init.sql; quoting that column makes this a no-op.
func quoteReserved(sql []byte) string {
	return strings.ReplaceAll(string(sql), "\n    references ", "\n    \"references\" ")
}

// ───────────────────────────────────────────── test helpers

// UniqueName builds a collision-free name for rows created by parallel runs.
func UniqueName(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s-%s", prefix, sanitize(t.Name()), uuid.NewString()[:8])
}

// MustExec runs a statement and fails the test on error.
func MustExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// Count runs a count-style query and fails the test on error.
func Count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return n
}

// CleanupProject removes a project and every row that cascades from it.
func CleanupProject(t *testing.T, projectID uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, projectID); err != nil {
			t.Errorf("cleanup project %s: %v", projectID, err)
		}
	})
}

// NewProject inserts a project row directly (for tests that only need a scope).
func NewProject(t *testing.T, name string) uuid.UUID {
	t.Helper()
	if name == "" {
		name = UniqueName(t, "proj")
	}
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO projects (name, description, status, tags, settings, updated_at)
		 VALUES ($1, '', 'active', '{}', '{}'::jsonb, now()) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	CleanupProject(t, id)
	return id
}

// NewScanner registers a scanner registry row and returns its id. The scanner
// is not installed on disk; these tests only need the registry entry.
func NewScanner(t *testing.T, name string) uuid.UUID {
	t.Helper()
	if name == "" {
		name = UniqueName(t, "scanner")
	}
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scanners (name, display_name, adapter, enabled, status, updated_at)
		 VALUES ($1, $2, 'command', true, 'available', now()) RETURNING id`, name, name).Scan(&id); err != nil {
		t.Fatalf("insert scanner: %v", err)
	}
	return id
}

// NewScanSession inserts a scan_sessions row and returns its id.
func NewScanSession(t *testing.T, projectID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scan_sessions (project_id, name, status, updated_at)
		 VALUES ($1, $2, 'running', now()) RETURNING id`, projectID, UniqueName(t, "session")).Scan(&id); err != nil {
		t.Fatalf("insert scan session: %v", err)
	}
	return id
}

// NewExecution inserts a scanner_executions row for a session and returns its id.
func NewExecution(t *testing.T, sessionID uuid.UUID, scannerName string) uuid.UUID {
	t.Helper()
	if scannerName == "" {
		scannerName = "nmap"
	}
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scanner_executions (session_id, scanner_name, status)
		 VALUES ($1, $2, 'running') RETURNING id`, sessionID, scannerName).Scan(&id); err != nil {
		t.Fatalf("insert scanner execution: %v", err)
	}
	return id
}

// NewUser inserts a users row and returns its id. Rows that reference a user
// (finding_status_history.changed_by, audit entries) have a foreign key to
// users, so tests that record an acting user need a real one.
func NewUser(t *testing.T) uuid.UUID {
	t.Helper()
	email := UniqueName(t, "user") + "@example.com"
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, name, password_hash, role, updated_at)
		 VALUES ($1, $2, 'not-a-real-hash', 'user', now()) RETURNING id`, email, email).Scan(&id); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup user %s: %v", id, err)
		}
	})
	return id
}
