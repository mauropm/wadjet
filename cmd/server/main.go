// WADJET server entrypoint.
//
// 👁️ We see what your assets are hiding.
package main

import (
	"context"
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

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("👁️ WADJET listening on :%s (%s)", cfg.Port, cfg.Env)
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
