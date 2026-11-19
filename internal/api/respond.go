// Package api wires the REST API: routing, middleware, and shared
// JSON response helpers.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"
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

// DecodeJSON decodes a request body with a size limit. It rejects NUL bytes
// and invalid UTF-8 (VER-003: PostgreSQL rejects them deep in the stack,
// surfacing as opaque 500s — reject at the edge with a clear 400 instead).
func DecodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20) // 1 MiB
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body too large or unreadable")
	}
	if bytes.IndexByte(body, 0) >= 0 {
		return errors.New("body must not contain NUL bytes")
	}
	if !utf8.Valid(body) {
		return errors.New("body must be valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
