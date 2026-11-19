// Command seed provisions (or removes) the WADJET demonstration project
// directly in PostgreSQL. It is intentionally conservative:
//
//   - Creates ONE clearly-marked demo project with authorized lab targets,
//     an exclusion example, two scan profiles bound to the nmap scanner,
//     and two manually-discovered assets.
//   - NEVER seeds fake findings: findings must come from real scans against
//     the demo lab (see demo/README.md).
//   - Idempotent: running it again when the demo project exists is a no-op.
//   - `--cleanup` removes the demo project (cascades to its data).
//
// Usage:
//
//	go run ./demo/seed              # create (or no-op if present)
//	go run ./demo/seed --cleanup    # remove
//
// Connection uses $DATABASE_URL (defaults to the local development DB).
// All SQL is parameterized; no shell execution anywhere.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/database"
)

// demoProjectName is the single anchor row for all demo content.
const demoProjectName = "🧪 WADJET Demo Lab"

const defaultDatabaseURL = "postgres://wadjet:wadjet@localhost:5432/wadjet?sslmode=disable"

func main() {
	log.SetPrefix("wadjet-seed: ")
	log.SetFlags(0)

	cleanup := flag.Bool("cleanup", false, "remove the demo project and all its data")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: go run ./demo/seed [--cleanup]\n\nProvisions the %s demo project.\n\n", demoProjectName)
		flag.PrintDefaults()
	}
	flag.Parse()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = defaultDatabaseURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, err := database.Open(ctx, url)
	if err != nil {
		log.Fatalf("database unavailable: %v", err)
	}
	defer db.Close()

	if err := database.Migrate(ctx, db); err != nil {
		// Tolerate already-provisioned databases whose schema_migrations
		// naming predates the current runner; verify the tables instead.
		var ok bool
		if qErr := db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables
			   WHERE table_schema='public' AND table_name='projects')`).Scan(&ok); qErr != nil || !ok {
			log.Fatalf("migrations failed: %v (verification query error: %v)", err, qErr)
		}
	}

	var exit int
	if *cleanup {
		exit = runCleanup(ctx, db)
	} else {
		exit = runSeed(ctx, db)
	}
	os.Exit(exit)
}

// projectID looks up the demo project, returning ok=false when absent.
func projectID(ctx context.Context, db *database.DB) (id string, ok bool, err error) {
	err = db.QueryRow(ctx, `SELECT id::text FROM projects WHERE name = $1`, demoProjectName).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return "", false, nil
		}
		return "", false, err
	}
	return id, true, nil
}

func runSeed(ctx context.Context, db *database.DB) int {
	if _, ok, err := projectID(ctx, db); err != nil {
		log.Fatalf("lookup: %v", err)
	} else if ok {
		fmt.Printf("demo project %q already exists — nothing to do (use --cleanup first to recreate)\n", demoProjectName)
		return 0
	}

	err := db.InTx(ctx, func(tx pgx.Tx) error {
		return seedTx(ctx, tx)
	})
	if err != nil {
		log.Fatalf("seed failed: %v", err)
	}

	fmt.Printf("✔ created demo project %q\n", demoProjectName)
	fmt.Println("  • 6 authorized targets (lab service names), 1 excluded canary target")
	fmt.Println("  • profiles: 'Quick Discovery', 'Standard Assessment' (nmap-bound where registered)")
	fmt.Println("  • 2 manual assets tagged 'demo'")
	fmt.Println("  • NO findings were created — run a real scan (see demo/README.md)")
	return 0
}

func runCleanup(ctx context.Context, db *database.DB) int {
	tag, err := db.Exec(ctx, `DELETE FROM projects WHERE name = $1`, demoProjectName)
	if err != nil {
		log.Fatalf("cleanup failed: %v", err)
	}
	if tag.RowsAffected() == 0 {
		fmt.Printf("demo project %q not present — nothing removed\n", demoProjectName)
		return 0
	}
	fmt.Printf("✔ removed demo project %q (cascaded to its targets, profiles, assets, sessions, findings, reports)\n", demoProjectName)
	return 0
}

// ───────────────────────────────────────────── seeding

func seedTx(ctx context.Context, tx pgx.Tx) error {
	// 1 ─ project ----------------------------------------------------------------
	var projectIDStr string
	if err := tx.QueryRow(ctx,
		`INSERT INTO projects (name, description, status, tags, settings)
		 VALUES ($1, $2, 'active', $3, $4) RETURNING id::text`,
		demoProjectName,
		"DEMO DATA — WADJET demonstration environment. Points at the intentionally "+
			"vulnerable lab in demo/docker-compose.yml (private network wadjet-lab). "+
			"Safe to delete at any time via 'go run ./demo/seed --cleanup'.",
		[]string{"demo", "lab"},
		`{"demo": true}`,
	).Scan(&projectIDStr); err != nil {
		return fmt.Errorf("insert project: %w", err)
	}

	// 2 ─ targets ----------------------------------------------------------------
	type target struct {
		target, typ string
		excluded    bool
		note        string
	}
	targets := []target{
		{"juice-shop", "hostname", false, "OWASP Juice Shop — full-stack vulnerable web app (port 3000)"},
		{"webgoat", "hostname", false, "OWASP WebGoat — training web app (port 8080)"},
		{"http-banner", "hostname", false, "banner-rich nginx endpoint (port 80)"},
		{"tls-test", "hostname", false, "self-signed TLS endpoint, deprecated protocols (port 443)"},
		{"sshd", "hostname", false, "weak-config openssh demo (port 2222)"},
		{"noisy", "hostname", false, "multi-port socat listener (8000-8005)"},
		{"198.51.100.0/24", "cidr", true, "RFC 5737 documentation range — exclusion canary, must never be scanned"},
	}
	for _, t := range targets {
		if _, err := tx.Exec(ctx,
			`INSERT INTO project_targets (project_id, target, target_type, excluded, note)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (project_id, target, excluded) DO NOTHING`,
			projectIDStr, t.target, t.typ, t.excluded, t.note); err != nil {
			return fmt.Errorf("insert target %s: %w", t.target, err)
		}
	}

	// 3 ─ scanner registry (ensure nmap; mirror the Lead's registry shape) -------
	if _, err := tx.Exec(ctx,
		`INSERT INTO scanners (name, display_name, description, executable, adapter, enabled, capabilities)
		 VALUES ('nmap', 'Nmap', 'Network exploration and security auditing scanner',
		         'nmap', 'command', true, $1)
		 ON CONFLICT (name) DO NOTHING`,
		[]string{"port-discovery", "service-detection", "os-detection", "scripting"}); err != nil {
		return fmt.Errorf("ensure nmap scanner: %w", err)
	}
	var nmapScannerID string
	errNoScanner := tx.QueryRow(ctx, `SELECT id::text FROM scanners WHERE name = 'nmap'`).Scan(&nmapScannerID)

	// 4 ─ profiles ---------------------------------------------------------------
	type profile struct {
		name, desc, config string
		timeout            int
	}
	profiles := []profile{
		{"Quick Discovery", "Fast sweep of all authorized targets: top ports, no scripts.",
			`{"ports":"top-1000","timing":"T4","scripts":false}`, 300},
		{"Standard Assessment", "Version detection plus default NSE scripts and OS guess.",
			`{"ports":"1-10000","scripts":"default","os_detect":true,"timing":"T3"}`, 1800},
	}
	for i, p := range profiles {
		var profileID string
		if err := tx.QueryRow(ctx,
			`INSERT INTO scan_profiles (project_id, name, description, target_selection, excluded_targets, timeout_seconds, report_prefs)
			 VALUES ($1, $2, $3, '{}', $4, $5, $6) RETURNING id::text`,
			projectIDStr, p.name, p.desc,
			[]string{"198.51.100.0/24"}, p.timeout,
			fmt.Sprintf(`{"sections":["assets","services","findings"],"format":"pdf","demo":true,"order":%d}`, i),
		).Scan(&profileID); err != nil {
			return fmt.Errorf("insert profile %s: %w", p.name, err)
		}
		if errNoScanner == nil {
			if _, err := tx.Exec(ctx,
				`INSERT INTO scan_profile_scanners (profile_id, scanner_id, config, sort_order)
				 VALUES ($1, $2, $3, 0)
				 ON CONFLICT (profile_id, scanner_id) DO NOTHING`,
				profileID, nmapScannerID, p.config); err != nil {
				return fmt.Errorf("bind nmap to %s: %w", p.name, err)
			}
		}
	}

	// 5 ─ manual assets ----------------------------------------------------------
	assets := []struct {
		identity, typ, ip, hostname, desc string
	}{
		{"172.30.0.10", "web_app", "172.30.0.10", "juice-shop.lab",
			"Manually recorded: Juice Shop storefront (demo asset — inventory entry only)"},
		{"jumpbox.lab", "hostname", "", "jumpbox.lab",
			"Manually recorded: finance-zone jumpbox placeholder (demo asset — never scanned)"},
	}
	for _, a := range assets {
		if _, err := tx.Exec(ctx,
			`INSERT INTO assets (project_id, identity, asset_type, ip, hostname,
			                     status, discovery_source, description, tags)
			 VALUES ($1, $2, $3, $4, $5, 'active', 'manual', $6, $7)
			 ON CONFLICT (project_id, identity) DO NOTHING`,
			projectIDStr, a.identity, a.typ, nilIfEmpty(a.ip), nilIfEmpty(a.hostname),
			a.desc, []string{"demo"}); err != nil {
			return fmt.Errorf("insert asset %s: %w", a.identity, err)
		}
	}
	return nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
