package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// projectScopedPrefixes are path prefixes whose first dynamic segment is a
// project id: /projects/{id}/….
var projectScopedPrefixes = []string{"/projects/"}

// idLookups maps a single-segment resource prefix to a SQL that resolves the
// resource's owning project id. Cross-project access is answered 404 (no
// existence disclosure).
var idLookups = map[string]string{
	"/assets/":   `SELECT project_id FROM assets WHERE id = $1`,
	"/findings/": `SELECT project_id FROM findings WHERE id = $1`,
	"/scans/":    `SELECT project_id FROM scan_sessions WHERE id = $1`,
	"/reports/":  `SELECT project_id FROM reports WHERE id = $1`,
	"/profiles/": `SELECT project_id FROM scan_profiles WHERE id = $1`,
	"/targets/":  `SELECT project_id FROM project_targets WHERE id = $1`,
	"/sessions/": `SELECT project_id FROM scan_sessions WHERE id = $1`,
}

// ProjectAccessMiddleware enforces project isolation centrally (SEC-008): any
// authenticated request touching a project-scoped or resource-scoped path
// must reference a resource that exists and belongs to a project the caller
// may access. v1 is single-tenant: every authenticated user owns all
// projects; the middleware's value is (a) fail-closed existence checks and
// (b) a single choke point for future per-user membership.
func (s *Server) ProjectAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		trimmed := strings.TrimPrefix(path, "/api/v1")

		// /projects/{id}/… — validate {id} is an existing project.
		for _, pfx := range projectScopedPrefixes {
			if strings.HasPrefix(trimmed, pfx) {
				rest := strings.TrimPrefix(trimmed, pfx)
				seg, _ := splitFirst(rest, "/")
				if id, err := uuid.Parse(seg); err == nil {
					if !s.projectExists(r.Context(), id) {
						WriteError(w, http.StatusNotFound, "not found")
						return
					}
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		// /{resource}/{id} — resolve owning project.
		for pfx, sqlq := range idLookups {
			if !strings.HasPrefix(trimmed, pfx) {
				continue
			}
			rest := strings.TrimPrefix(trimmed, pfx)
			seg, _ := splitFirst(rest, "/")
			id, err := uuid.Parse(seg)
			if err != nil {
				next.ServeHTTP(w, r) // non-uuid path params: resource handlers 400 as before
				return
			}
			if !s.resourceProjectExists(r.Context(), sqlq, id) {
				WriteError(w, http.StatusNotFound, "not found")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func splitFirst(s, sep string) (string, string) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func (s *Server) projectExists(ctx context.Context, id uuid.UUID) bool {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1)`, id).Scan(&ok)
	return err == nil && ok
}

func (s *Server) resourceProjectExists(ctx context.Context, sqlq string, id uuid.UUID) bool {
	var ok bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(`+sqlq+`)`, id).Scan(&ok)
	return err == nil && ok
}
