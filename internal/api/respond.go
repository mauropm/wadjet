// Package api wires the REST API: routing, middleware, and shared
// JSON response helpers.
package api

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes an entity response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// WriteList writes a list response in the standard envelope.
func WriteList[T any](w http.ResponseWriter, items []T, total int) {
	if items == nil {
		items = []T{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// WriteError writes the standard error envelope.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]any{
		"error": map[string]string{"message": message},
	})
}

// DecodeJSON decodes a request body with a size limit.
func DecodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20) // 1 MiB
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
