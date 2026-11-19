package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/mauropm/wadjet/internal/models"
)

type ctxKey int

const userCtxKey ctxKey = 1

// UserFromContext returns the authenticated user injected by the middleware.
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
			WriteError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.Split(fwd, ",")[0]
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
