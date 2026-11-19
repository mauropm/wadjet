package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

type decodeTarget struct {
	Title  string              `json:"title"`
	Tags   []string            `json:"tags"`
	Meta   map[string]string   `json:"meta"`
	Nested *struct{ S string } `json:"nested"`
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
	esc := `\u0000` // the JSON escape sequence, six characters

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
