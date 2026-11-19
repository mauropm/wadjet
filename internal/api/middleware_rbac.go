package api

import (
	"net/http"
)

// RequireAdmin restricts a route to admin-role users (SEC-002: RBAC).
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		if u == nil || u.Role != "admin" {
			WriteError(w, http.StatusForbidden, "administrator role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin is the Server-bound form of the package-level RequireAdmin.
func (s *Server) RequireAdmin(next http.Handler) http.Handler { return RequireAdmin(next) }

// SecurityHeaders sets baseline response headers (SEC-011). The API serves
// only JSON and PDF/ZIP downloads, so a strict CSP is safe and blocks any
// future injection from becoming script execution.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
