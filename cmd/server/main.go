// WADJET server entrypoint.
//
// 👁️ We see what your assets are hiding.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mauropm/wadjet/internal/api"
	"github.com/mauropm/wadjet/internal/assets"
	"github.com/mauropm/wadjet/internal/audit"
	"github.com/mauropm/wadjet/internal/auth"
	"github.com/mauropm/wadjet/internal/config"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
	"github.com/mauropm/wadjet/internal/findings"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/orchestration"
	"github.com/mauropm/wadjet/internal/profiles"
	"github.com/mauropm/wadjet/internal/projects"
	"github.com/mauropm/wadjet/internal/reports"
	"github.com/mauropm/wadjet/internal/scanners/registry"
	"github.com/mauropm/wadjet/internal/scans"
	"github.com/mauropm/wadjet/internal/targets"
)

// mustList is a soft-failing registry list used for best-effort startup
// health checks.
func mustList(ctx context.Context, r *registry.Registry) []models.ScannerRecord {
	recs, _ := r.List(ctx)
	return recs
}

func main() {
	cfg := config.Load()

	// SECURITY (SEC-006): never run production with the default signing
	// secret — anyone could mint valid session credentials.
	if !cfg.IsDevelopment() && cfg.SessionSecret == "dev-se…e-me" {
		log.Fatal("wadjet: refusing to start in production with the default WADJET_SESSION_SECRET")
	}
	if cfg.SessionSecret == "dev-se…e-me" {
		log.Printf("wadjet: WARNING — using default session secret; set WADJET_SESSION_SECRET before any non-local deployment")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("wadjet: database unavailable: %v", err)
	}
	defer db.Close()

	if err := database.Migrate(ctx, db); err != nil {
		log.Fatalf("wadjet: migrations failed: %v", err)
	}

	authService := auth.NewService(db, cfg.SessionSecret)
	// SECURITY (SEC-005): production must not boot with the shipped default
	// admin password — anyone knowing the product can claim the instance.
	if cfg.AdminPassword == "wadjet-admin" {
		if !cfg.IsDevelopment() {
			log.Fatal("wadjet: refusing to start in production with the default WADJET_ADMIN_PASSWORD")
		}
		log.Printf("wadjet: WARNING — using default admin password; set WADJET_ADMIN_PASSWORD before any non-local deployment")
	}
	if err := authService.EnsureAdmin(ctx, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("wadjet: bootstrap admin failed: %v", err)
	}
	// Development no-login mode (`make dev`) impersonates this account on
	// every unauthenticated request. SEC-DEV-1: the flag is honoured only
	// when WADJET_ENV is *exactly* "development" — an ambiguous value
	// ("Production", "prod", a typo) combined with a leaked flag is a
	// configuration contradiction, so refuse the boot instead of guessing.
	devNoLogin := os.Getenv("WADJET_DEV_NO_LOGIN") == "1"
	if devNoLogin {
		if !cfg.IsStrictDevelopment() {
			log.Fatalf("wadjet: refusing to start: WADJET_DEV_NO_LOGIN=1 requires WADJET_ENV=development exactly (got %q)", cfg.Env)
		}
		// The account must exist even in databases already seeded with
		// other users (EnsureAdmin only bootstraps empties). SEC-DEV-2: it
		// gets a random per-boot password, never the shipped default, so no
		// publicly-known credential is ever persisted into a shared DB —
		// no-login mode needs the row only as a principal, not its password.
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			log.Fatalf("wadjet: dev no-login admin setup failed: %v", err)
		}
		if err := authService.EnsureUserByEmail(ctx, cfg.AdminEmail, "Administrator", hex.EncodeToString(nonce), "admin"); err != nil {
			log.Fatalf("wadjet: dev no-login admin setup failed: %v", err)
		}
	}

	for _, dir := range []string{cfg.ReportDir, cfg.RawOutputDir, cfg.ScanWorkDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			log.Fatalf("wadjet: cannot create storage dir %s: %v", dir, err)
		}
	}

	bus := events.New()
	auditLogger := audit.NewLogger(db)

	// Domain services (ownership per docs/CONTRACTS.md), wired via
	// dependency injection at this single composition root.
	projectsSvc := projects.NewService(db, auditLogger)
	targetsSvc := targets.NewService(db)
	assetsSvc := assets.NewService(db)
	findingsSvc := findings.NewService(db, assetsSvc, auditLogger)
	profilesSvc := profiles.NewService(db)

	scannerRegistry := registry.New(db)
	if err := scannerRegistry.Load(ctx, cfg.ScannerCfgDir); err != nil {
		// A broken manifest must not prevent booting with the rest.
		log.Printf("wadjet: scanner manifest load issue: %v", err)
	}
	go func() { // populate version/availability without blocking boot
		checkCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		for _, rec := range mustList(checkCtx, scannerRegistry) {
			if _, err := scannerRegistry.CheckAvailability(checkCtx, rec.Name); err != nil {
				log.Printf("wadjet: scanner %s availability check failed: %v", rec.Name, err)
			}
		}
	}()

	orchestrator := orchestration.New(db, scannerRegistry, findingsSvc, bus, targetsSvc, orchestration.Options{
		Concurrency:    cfg.ScanConcurrency,
		DefaultTimeout: time.Duration(cfg.ScanTimeout) * time.Second,
		RawOutputDir:   cfg.RawOutputDir,
		WorkDir:        cfg.ScanWorkDir,
	})
	scansSvc := scans.NewService(db, scannerRegistry, orchestrator, bus)
	reportsSvc := reports.NewService(db, cfg, bus, auditLogger)

	// VER-006: fail sessions/executions orphaned by a previous process.
	if err := orchestrator.RecoverInterrupted(ctx); err != nil {
		log.Printf("wadjet: scan recovery warning: %v", err)
	}

	extra := []api.Registrable{
		projectsSvc, targetsSvc, assetsSvc, findingsSvc, profilesSvc,
		scansSvc, reportsSvc,
	}

	handler := api.NewServer(cfg, db, authService, auditLogger, bus, extra)

	// SEC-DEV-3: with no-login mode active the listener hands full admin to
	// any unauthenticated network peer, so bind loopback unless the operator
	// explicitly asks for all interfaces.
	bind := ":" + cfg.Port
	if devNoLogin {
		if os.Getenv("WADJET_DEV_BIND_ALL") == "1" {
			log.Printf("wadjet: WARNING — WADJET_DEV_NO_LOGIN with WADJET_DEV_BIND_ALL=1: unauthenticated admin on every interface")
		} else {
			bind = "127.0.0.1:" + cfg.Port
		}
		log.Printf("wadjet: WARNING — WADJET_DEV_NO_LOGIN=1: unauthenticated requests are served as admin %s (local development only)", cfg.AdminEmail)
	}

	srv := &http.Server{
		Addr:              bind,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("👁️ WADJET listening on %s (%s)", bind, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("wadjet: server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("wadjet: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
