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
	"github.com/mauropm/wadjet/internal/audit"
	"github.com/mauropm/wadjet/internal/auth"
	"github.com/mauropm/wadjet/internal/config"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
)

func main() {
	cfg := config.Load()

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

	// Domain services (projects, assets, findings, scanners, orchestration,
	// reports) register additional routes here.
	var extra []api.Registrable

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
