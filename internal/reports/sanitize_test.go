package reports

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ───────────────────────────────────────────── sanitizeText

func TestSanitizeTextStripsControls(t *testing.T) {
	got := sanitizeText("a\x00b\x01c\x07d\x1be\x7Ff")
	assert.Equal(t, "abcdef", got, "C0 controls and DEL must be removed")

	got = sanitizeText("line1\nline2\tcol")
	assert.Equal(t, "line1\nline2\tcol", got, "\\n and \\t must survive")

	got = sanitizeText("crlf\r\nx")
	assert.Equal(t, "crlf\nx", got, "CR collapses into LF")

	// C1 range and invisible directionality characters.
	got = sanitizeText("a\u0085b\u200bc\u202ed\ufeffe")
	assert.Equal(t, "abcde", got)
}

func TestCapText(t *testing.T) {
	assert.Equal(t, "hello", capText("hello", 10))
	assert.Equal(t, "hello", capText("hello", 5), "exactly max stays intact")
	assert.Equal(t, "hel"+truncMarker, capText("hello", 3))

	// Rune-based: multibyte characters are never cut mid-rune.
	src := "日本語テスト"
	got := capText(src, 3)
	assert.Equal(t, "日本語"+truncMarker, got, "cut at rune boundary, marker appended once")

	// 10k evidence cap boundary.
	long := strings.Repeat("x", MaxEvidenceLen+500)
	capped := capText(sanitizeText(long), MaxEvidenceLen)
	assert.Equal(t, MaxEvidenceLen+len([]rune(truncMarker)), len([]rune(capped)))

	assert.Equal(t, "", capText("", 10))
	assert.Equal(t, long, capText(long, 0), "max<=0 disables the cap")
}

// ───────────────────────────────────────────── pdfText

func TestPDFTextTranscodes(t *testing.T) {
	// printable ASCII untouched
	assert.Equal(t, "abc XYZ 0-9", pdfText("abc XYZ 0-9"))
	// Latin-1 supplement passes through as its own byte
	assert.Equal(t, "caf\xe9 na\xefve", pdfText("café naïve"))
	// CP1252 specials map to their WinAnsi bytes
	assert.Equal(t, "\x97", pdfText("—"), "em dash")
	assert.Equal(t, "\x96", pdfText("–"), "en dash")
	assert.Equal(t, "\x85", pdfText("…"), "ellipsis")
	assert.Equal(t, "\x91\x92", pdfText("\u2018\u2019"), "curly singles")
	assert.Equal(t, "\x93\x94", pdfText("\u201C\u201D"), "curly doubles")
	assert.Equal(t, "\x95", pdfText("•"), "bullet")
	assert.Equal(t, "\x80", pdfText("€"), "euro")
	// non-representable runes become '?'
	assert.Equal(t, "?", pdfText("👁"), "emoji")
	assert.Equal(t, "??", pdfText("日本"), "CJK")
	// control characters never survive
	assert.Equal(t, "ok", pdfText("\x00o\x1bk"))
	// newline/tab retained for wrapping logic
	assert.Equal(t, "a\nb\tc", pdfText("a\nb\tc"))
	// output is pure WinAnsi bytes: high bytes only in the Latin-1 print
	// range or the mapped CP1252 special slots.
	allowed := map[byte]bool{}
	for _, b := range cp1252Specials {
		allowed[b] = true
	}
	for by := 0xA0; by <= 0xFF; by++ {
		allowed[byte(by)] = true
	}
	out := pdfText("café — 👁 \x07end\nx\ty")
	for _, by := range []byte(out) {
		if by > 0x7E {
			assert.True(t, allowed[by], "unexpected high byte %#x in output", by)
		}
	}
	// WinAnsi output: é is the raw 0xE9 byte, not UTF-8.
	assert.Equal(t, "caf\xe9 \x97 ? end\nx\ty", out)
}

func TestPDFTextIsLayoutSafe(t *testing.T) {
	// A pathological single "word" must not crash the wrapping primitives.
	huge := strings.Repeat("A👁\x00", 4000)
	out := pdfText(capText(sanitizeText(huge), MaxEvidenceLen))
	assert.NotEmpty(t, out)
	for _, r := range out {
		if r > 0x7E {
			t.Fatalf("byte %#x escaped pdfText", r)
		}
	}
}

// ───────────────────────────────────────────── slugs & filenames

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"🧪 WADJET Demo Lab": "wadjet-demo-lab",
		"My App!!!":         "my-app",
		"  ":                "project",
		"!!!???":            "project",
		"CamelCase Name":    "camelcase-name",
		"trailing-":         "trailing",
		"multi   space":     "multi-space",
		"slashes/\\back":    "slashes-back",
		"héllo wörld":       "hello-world",
	}
	for in, want := range cases {
		assert.Equal(t, want, slugify(in), "slugify(%q)", in)
	}
	// Collisions: different names collapsing to one slug is expected and
	// safe because report filenames embed the report UUID.
	assert.Equal(t, slugify("Foo Bar"), slugify("foo--bar"))
	a := slugify("Proj α")
	b := slugify("Proj β")
	assert.Equal(t, a, b, "non-ASCII variants share a slug")
	assert.NotEmpty(t, a)
}

func TestFileSafe(t *testing.T) {
	assert.Equal(t, "scan-abc-1234.pdf", fileSafe("scan-abc-1234.pdf"))
	assert.Equal(t, "report", fileSafe(""))
	assert.Equal(t, "report", fileSafe("///"))
	got := fileSafe("../../etc/passwd")
	assert.NotContains(t, got, "/")
	assert.NotContains(t, got, "..")
	got = fileSafe("a b\"c;d\ne")
	for _, r := range got {
		ok := r == '.' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		require.True(t, ok, "unsafe rune %U in %q", r, got)
	}
}

func TestIsPathSafe(t *testing.T) {
	assert.True(t, isPathSafe("wadjet-demo-lab/scan-uuid-20261118-2300.pdf"))
	assert.False(t, isPathSafe(""))
	assert.False(t, isPathSafe("/abs/x.pdf"))
	assert.False(t, isPathSafe("a/../b.pdf"))
	assert.False(t, isPathSafe("a//b.pdf"))
	assert.False(t, isPathSafe("a\\b.pdf"))
	assert.False(t, isPathSafe("a\x00b.pdf"))
}

func TestCollapseWhitespace(t *testing.T) {
	assert.Equal(t, "a b c", collapseWhitespace(" a\n\tb\x00  c "))
}

// ───────────────────────────────────────────── observedPorts

func TestObservedPortsDecodes(t *testing.T) {
	raw := []byte(`{"ports":[
		{"port":80,"protocol":"tcp","service":"http","state":"open","version":"nginx 1.25"},
		{"port":99999,"protocol":"tcp","state":"open"},
		{"protocol":"tcp","state":"open"},
		{"port":22,"protocol":"tcp","service":"ssh","state":"closed"}],
		"services":[{"port":443,"protocol":"tcp","service":"https","state":"open","product":"openssl"}]}`)
	ports := observedPorts(raw)
	require.Len(t, ports, 3, "invalid port entries dropped")
	assert.Equal(t, 80, ports[0].Port)
	assert.Equal(t, "open", ports[0].State)
	assert.Equal(t, 22, ports[1].Port)
	assert.Equal(t, 443, ports[2].Port)
	assert.Equal(t, "openssl", ports[2].Version, "product used as version fallback")

	assert.Nil(t, observedPorts(nil))
	assert.Nil(t, observedPorts([]byte(`not json`)), "malformed payload ignored")
	assert.Nil(t, observedPorts([]byte(`{"ports":"nonsense"}`)), "wrong shape ignored")
}
