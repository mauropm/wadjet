package findings

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/mauropm/wadjet/internal/assets/itest"
	"github.com/mauropm/wadjet/internal/database"
)

// Temporary probe: does the real database.Migrate still work on a fresh
// database now that the Lead quoted the reserved word in 0001_init.sql?
func TestFreshMigrateWorks(t *testing.T) {
	ctx := context.Background()
	raw := itest.DatabaseURL()
	if v := os.Getenv("WADJET_TEST_DATABASE_URL"); v != "" {
		raw = v
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	u.Path = "/postgres"
	admin, err := database.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	defer admin.Close()
	name := "wadjet_probe_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	}()
	u.Path = "/" + name
	db, err := database.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open fresh db: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("database.Migrate on a fresh database: %v", err)
	}
	var tables int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	t.Logf("fresh migrate produced %d public tables", tables)
	if tables < 20 {
		t.Fatalf("only %d tables created", tables)
	}
}
