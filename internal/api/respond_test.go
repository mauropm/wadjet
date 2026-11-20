package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
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

// binaryTarget mirrors the DTO shapes that exposed a false positive in the
// NUL walk: the raw-payload branch used to match ANY byte-typed aggregate,
// including uuid.UUID (a [16]byte ARRAY whose binary form contains a zero
// byte in ~39% of random values) and base64-decoded []byte fields. Valid
// requests were 400-ing at random until the branch was restricted to
// json.RawMessage proper.
type binaryTarget struct {
	ID   uuid.UUID  `json:"id"`
	Opt  *uuid.UUID `json:"opt"`
	Blob []byte     `json:"blob"`
}

func decodeBinary(t *testing.T, body string) error {
	t.Helper()
	r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
	var dst binaryTarget
	return DecodeJSON(r, &dst)
}

func TestDecodeJSONBinaryAggregates(t *testing.T) {
	cases := map[string]string{
		// All-zero UUID: every one of the 16 bytes is NUL in binary form.
		"all-zero uuid":        `{"id":"00000000-0000-0000-0000-000000000000"}`,
		"uuid with zero bytes": `{"id":"de8f00ad-00be-4f00-9d01-00c9a1b2c3d4"}`,
		// base64 "AAECAwQFAAA=" decodes to 00 01 02 03 04 05 00.
		"base64 blob with NULs":  `{"id":"00000000-0000-0000-0000-000000000000","blob":"AAECAwQFAAA="}`,
		"uuid pointer with NULs": `{"id":"11111111-1111-1111-1111-111111111111","opt":"00000000-0000-4000-8000-000000000000"}`,
	}
	for name, body := range cases {
		if err := decodeBinary(t, body); err != nil {
			t.Errorf("%s: valid body rejected: %v", name, err)
		}
	}

	// The walk must still guard the OTHER parts of such DTOs: a NUL-escaped
	// string alongside a binary field is still refused.
	esc := "\\" + "u0000"
	type mixedTarget struct {
		ID    uuid.UUID `json:"id"`
		Title string    `json:"title"`
	}
	r := httptest.NewRequest("POST", "/x", strings.NewReader(`{"id":"de8f00ad-00be-4f00-9d01-00c9a1b2c3d4","title":"evil`+esc+`value"}`))
	var dst mixedTarget
	if err := DecodeJSON(r, &dst); err == nil {
		t.Error("escaped NUL in string field of a binary-carrying DTO accepted")
	}
}
