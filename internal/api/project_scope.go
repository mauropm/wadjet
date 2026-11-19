package api

import (
	"net/http"

	"github.com/google/uuid"
)

// ProjectScopeMatches enforces VER-002 (defense-in-depth project isolation):
// single-tenant deployments may access resources by direct id, but whenever a
// caller states a project scope (?project_id= or X-Project-Id), the resource
// must belong to that project. Returns true when no scope is stated or when
// it matches.
func ProjectScopeMatches(r *http.Request, owner uuid.UUID) bool {
	raw := r.URL.Query().Get("project_id")
	if raw == "" {
		raw = r.Header.Get("X-Project-Id")
	}
	if raw == "" {
		return true
	}
	pid, err := uuid.Parse(raw)
	if err != nil {
		return false // malformed scope stated: deny
	}
	return pid == owner
}
