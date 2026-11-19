package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

type decodeTarget struct {
	Title  string              `json:"title"`
	Tags   []string            `json:"tags"`
	Meta   map[string]string   `json:"meta"`
	Nested *struct{ S string } `json:"nested"`
	Fields json.RawMessage     `json:"fields,omitempty"`
}

// decode runs DecodeJSON over the given raw body text.
func decode(t *testing.T, body string) error {
	t.Helper()
	r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
	var dst decodeTarget
	return DecodeJSON(r, &dst)
}

// TestDecodeJSONNULRejection covers VER-003 and its DEF-1 bypass: both a
// raw NUL byte and its JSON escape sequence (which materializes only
// after decoding) must be refused at the edge — PostgreSQL rejects them
// later as opaque 500s.
func TestDecodeJSONNULRejection(t *testing.T) {
	if err := decode(t, `{"title":"ok","tags":["a"],"meta":{"k":"v"},"nested":{"S":"deep"}}`); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}

	// the escape token below is built at runtime so this
	// source file never embeds control bytes literally.
	nul := "\x00"
	esc := "\\" + "u0000"

	cases := map[string]string{
		"raw NUL byte in body":         `{"title":"a` + nul + `b"}`,
		"escaped NUL in top-level":     `{"title":"a` + esc + `b"}`,
		"escaped NUL in slice element": `{"tags":["ok","` + esc + `"]}`,
		"escaped NUL in map value":     `{"meta":{"k":"` + esc + `"}}`,
		"escaped NUL in nested struct": `{"nested":{"S":"x` + esc + `y"}}`,
	}
	for name, body := range cases {
		if err := decode(t, body); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}

	// A literal backslash-u sequence (double-escaped backslash) is ordinary
	// text and must pass — the guard inspects decoded values, not substrings.
	if err := decode(t, `{"title":"the text \\u0000 is fine"}`); err != nil {
		t.Errorf("double-escaped literal rejected: %v", err)
	}

	// Baseline: DisallowUnknownFields still in force.
	if err := decode(t, `{"nope":1}`); err == nil {
		t.Error("unknown field accepted")
	}
}

// TestDecodeJSONRawMessageNUL covers NEW-2: json.RawMessage DTO fields
// (e.g. project settings) keep \u0000 escapes verbatim, and PostgreSQL
// rejects them later in jsonb as an opaque 500. The walk must re-decode
// byte-slice fields and reject them at the edge.
func TestDecodeJSONRawMessageNUL(t *testing.T) {
	if err := decode(t, `{"title":"ok","fields":{"k":"plain value"}}`); err != nil {
		t.Fatalf("clean raw field rejected: %v", err)
	}
	esc := "\\" + "u0000"
	if err := decode(t, `{"title":"ok","fields":{"k":"evil`+esc+`value"}}`); err == nil {
		t.Error("escaped NUL inside RawMessage accepted")
	}
	if err := decode(t, `{"title":"ok","fields":{"deep":{"k":["x`+esc+`y"]}}}`); err == nil {
		t.Error("escaped NUL nested inside RawMessage accepted")
	}
	// Non-JSON payloads are the caller's business, not the edge guard's.
	if err := decode(t, `{"title":"ok","fields":"plain-string-not-json"}`); err != nil {
		t.Errorf("non-JSON raw payload rejected: %v", err)
	}
}
