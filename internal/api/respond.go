// Package api wires the REST API: routing, middleware, and shared
// JSON response helpers.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
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
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// DEF-1: JSON-escaped "\u0000" survives the raw-byte check above and
	// decodes into Go strings as a real NUL, which PostgreSQL rejects deep
	// in the stack as an opaque 500 (same class as VER-003). Walk the
	// decoded value and fail the request at the edge with a clear 400.
	if decodedHasNUL(reflect.ValueOf(dst)) {
		return errors.New("body must not contain NUL characters")
	}
	return nil
}

// decodedHasNUL recursively inspects decoded JSON values (structs, maps,
// slices, pointers, interfaces) for strings carrying a NUL byte.
func decodedHasNUL(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return strings.IndexByte(v.String(), 0) >= 0
	case reflect.Pointer, reflect.Interface:
		return !v.IsNil() && decodedHasNUL(v.Elem())
	case reflect.Slice, reflect.Array:
		// Byte slices carry raw JSON payloads (json.RawMessage): their NULs
		// live in the body as \u0000 escapes and survive verbatim into
		// jsonb columns, where PostgreSQL rejects them later as an opaque
		// 500 (same class as DEF-1 — NEW-2). Re-decode and walk the value.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.Len() == 0 {
				return false
			}
			raw := v.Slice(0, v.Len()).Bytes()
			if bytes.IndexByte(raw, 0) >= 0 {
				return true
			}
			var inner any
			if err := json.Unmarshal(raw, &inner); err == nil {
				return decodedHasNUL(reflect.ValueOf(inner))
			}
			return false // non-JSON bytes: callers validate their own payloads
		}
		for i := 0; i < v.Len(); i++ {
			if decodedHasNUL(v.Index(i)) {
				return true
			}
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if decodedHasNUL(k) || decodedHasNUL(v.MapIndex(k)) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if decodedHasNUL(v.Field(i)) {
				return true
			}
		}
	}
	return false
}
