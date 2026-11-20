package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/mauropm/wadjet/internal/models"
)

type ctxKey int

const userCtxKey ctxKey = 1

// UserFromContext returns the authenticated user injected by the middleware.
// WithUser returns a request carrying u as the authenticated principal.
// Used by AuthMiddleware and by service tests exercising role-gated routes.
func WithUser(r *http.Request, u *models.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, u))
}

func UserFromContext(ctx context.Context) *models.User {
	u, _ := ctx.Value(userCtxKey).(*models.User)
	return u
}

// AuthMiddleware validates the bearer/cookie session token.
func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			if c, err := r.Cookie("wadjet_session"); err == nil {
				token = c.Value
			}
		}
		user, err := s.auth.Authenticate(r.Context(), token)
		if err != nil {
			if dev := s.devBypassUser(r.Context()); dev != nil {
				next.ServeHTTP(w, WithUser(r, dev))
				return
			}
			WriteError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// devBypassUser implements the `make dev` local-development convenience:
// when WADJET_DEV_NO_LOGIN=1 AND WADJET_ENV is exactly "development",
// unauthenticated requests are served as the bootstrap admin (a real users
// row, so created_by foreign keys stay valid).
//
// SECURITY: this is a login *convenience for local development*, not an
// access-control feature. It is inert unless BOTH conditions hold —
// IsStrictDevelopment (allowlist: a leaked flag + an env typo like
// "Production" is NOT enough, SEC-DEV-1) and the explicit flag — so a
// production boot can never impersonate. The principal is resolved per
// request, never cached, so demoting or deleting the admin row takes
// effect immediately (SEC-DEV-5). Returns nil (deny, the caller 401s)
// otherwise.
func (s *Server) devBypassUser(ctx context.Context) *models.User {
	if !s.cfg.IsStrictDevelopment() || os.Getenv("WADJET_DEV_NO_LOGIN") != "1" {
		return nil
	}
	u, err := s.auth.UserByEmail(ctx, s.cfg.AdminEmail)
	if err != nil {
		slog.Warn("api: dev no-login mode could not resolve the bootstrap admin",
			"email", s.cfg.AdminEmail, "err", err)
		return nil
	}
	if u.Role != "admin" {
		return nil // never impersonate a non-admin account
	}
	return u
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// TokenFromRequest extracts the session token for logout.
func TokenFromRequest(r *http.Request) string {
	if t := bearerToken(r); t != "" {
		return t
	}
	if c, err := r.Cookie("wadjet_session"); err == nil {
		return c.Value
	}
	return ""
}

// ───────────────────────────── rate limiting

type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	limits   map[string]rate.Limit
	seen     map[string]time.Time
}

// NewIPLimiter builds a per-IP limiter keyed by path prefix.
// prefixes maps e.g. "/api/v1/auth" to events-per-second.
func NewIPLimiter(prefixes map[string]rate.Limit) func(http.Handler) http.Handler {
	lim := &ipLimiter{
		limiters: map[string]*rate.Limiter{},
		limits:   prefixes,
		seen:     map[string]time.Time{},
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			prefix, limit := matchPrefix(lim.limits, r.URL.Path)
			if limit == 0 {
				next.ServeHTTP(w, r)
				return
			}
			key := clientIP(r) + "|" + prefix
			lim.mu.Lock()
			rl, ok := lim.limiters[key]
			if !ok {
				rl = rate.NewLimiter(limit, int(limit)*5+10)
				lim.limiters[key] = rl
			}
			lim.seen[key] = time.Now()
			if len(lim.limiters) > 10000 {
				for k, t := range lim.seen {
					if time.Since(t) > time.Hour {
						delete(lim.limiters, k)
						delete(lim.seen, k)
					}
				}
			}
			lim.mu.Unlock()
			if !rl.Allow() {
				WriteError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func matchPrefix(limits map[string]rate.Limit, path string) (string, rate.Limit) {
	best, bestLimit := "", rate.Limit(0)
	for p, l := range limits {
		if strings.HasPrefix(path, p) && len(p) > len(best) {
			best, bestLimit = p, l
		}
	}
	return best, bestLimit
}

func clientIP(r *http.Request) string {
	// SECURITY: X-Forwarded-For is spoofable and must never be trusted by
	// default — it would let any client pick its own rate-limit bucket (and
	// forge audit-log IPs). Only honor it behind a trusted reverse proxy,
	// opted in with WADJET_TRUST_PROXY=1 (e.g. running behind nginx/Traefik).
	if os.Getenv("WADJET_TRUST_PROXY") == "1" {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// Rightmost entry: under the standard proxy_add_x_forwarded_for
			// config the leftmost entry is client-authored (spoofable); the
			// rightmost was appended by our own trusted proxy.
			parts := strings.Split(fwd, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
