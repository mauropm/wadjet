package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"

	"github.com/mauropm/wadjet/internal/audit"
	"github.com/mauropm/wadjet/internal/auth"
	"github.com/mauropm/wadjet/internal/config"
	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
)

// Registrable is implemented by every domain service so the router can
// mount it without importing the concrete package at scaffold time.
type Registrable interface {
	Register(r chi.Router)
}

// Server holds shared dependencies for the HTTP API.
type Server struct {
	cfg   *config.Config
	db    *database.DB
	auth  *auth.Service
	audit *audit.Logger
	bus   *events.Bus
}

// NewServer constructs the API server. extra services are mounted under
// /api/v1 behind the auth middleware.
func NewServer(cfg *config.Config, db *database.DB, authService *auth.Service, auditLogger *audit.Logger, bus *events.Bus, extra []Registrable) http.Handler {
	s := &Server{cfg: cfg, db: db, auth: authService, audit: auditLogger, bus: bus}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(NewIPLimiter(map[string]rate.Limit{
		"/api/v1/auth": rate.Limit(0.5), // ~30 login attempts per minute per IP
		"/api/v1":      rate.Limit(50),
	}))

	if cfg.IsDevelopment() {
		r.Use(corsDev)
	}

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "wadjet"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", s.handleLogin)
			r.Post("/register", s.handleRegister)
			r.With(s.AuthMiddleware).Post("/logout", s.handleLogout)
			r.With(s.AuthMiddleware).Get("/me", s.handleMe)
		})
		r.Get("/events", s.handleEvents) // SSE, authenticated
		r.Group(func(r chi.Router) {
			r.Use(s.AuthMiddleware)
			for _, svc := range extra {
				svc.Register(r)
			}
		})
	})
	return r
}

// corsDev allows the Vite dev server (port 5173) during development.
func corsDev(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://localhost:5173" || origin == "http://127.0.0.1:5173" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
