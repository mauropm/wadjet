// Package reports renders professional WADJET PDF deliverables (scan
// reports, standalone finding advisories, consolidated finding reports and
// ZIP bundles) from data stored in PostgreSQL, serves them through the REST
// API and manages their asynchronous generation lifecycle.
//
// All text that reaches the PDF layer originates from UNTRUSTED scanner
// output; everything is sanitized, length-capped and transcoded to the
// WinAnsi/Latin-1 repertoire of the core Helvetica/Courier fonts before
// being handed to gofpdf (see sanitize.go).
package reports

import "strings"

// Length caps (in runes) enforced on untrusted scanner-supplied text.
const (
	MaxEvidenceLen    = 10000
	MaxDescriptionLen = 5000
	MaxTechnicalLen   = 10000
	MaxTitleLen       = 300
	MaxLineLen        = 1000 // any single logical line beyond this is capped
)

// truncMarker is appended (rune-wise) to text shortened by capText.
const truncMarker = "…[truncated]"

// cp1252Specials maps Unicode code points that are representable in the
// Windows-1252 (WinAnsi) encoding used by the PDF core fonts but that do
// not sit at their Unicode code point in Latin-1. Anything outside this
// map and outside printable Latin-1 becomes '?' (see pdfText).
var cp1252Specials = map[rune]byte{
	'\u20AC': 0x80, // €
	'\u201A': 0x82, // ‚
	'\u0192': 0x83, // ƒ
	'\u201E': 0x84, // „
	'\u2026': 0x85, // …
	'\u2020': 0x86, // †
	'\u2021': 0x87, // ‡
	'\u02C6': 0x88, // ˆ
	'\u2030': 0x89, // ‰
	'\u0160': 0x8A, // Š
	'\u2039': 0x8B, // ‹
	'\u0152': 0x8C, // Œ
	'\u017D': 0x8E, // Ž
	'\u2018': 0x91, // '
	'\u2019': 0x92, // '
	'\u201C': 0x93, // "
	'\u201D': 0x94, // "
	'\u2022': 0x95, // •
	'\u2013': 0x96, // –
	'\u2014': 0x97, // —
	'\u02DC': 0x98, // ˜
	'\u2122': 0x99, // ™
	'\u0161': 0x9A, // š
	'\u203A': 0x9B, // ›
	'\u0153': 0x9C, // œ
	'\u017E': 0x9E, // ž
	'\u0178': 0x9F, // Ÿ
}

// isDangerous reports whether r is a control or invisible-directionality
// character that must never reach the rendered document. Layout characters
// \n and \t are kept; every other C0 character, DEL, the C1 range and the
// common zero-width/bidi/RTL-override code points are removed.
func isDangerous(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case r < 0x20, r == 0x7F:
		return true
	case r >= 0x80 && r <= 0x9F: // C1 controls
		return true
	}
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, // zero-width & LTR/RTL marks
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // bidi embedding/override
		0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // word joiners
		0xFEFF: // BOM
		return true
	}
	return false
}

// sanitizeText strips control and invisible Unicode characters from
// untrusted input. Newlines and tabs are preserved (the layout layer turns
// them into wrapped lines). CR is dropped so CRLF becomes a plain LF.
func sanitizeText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isDangerous(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// capText truncates s to max runes, appending the truncation marker when
// text was removed. max <= 0 removes the cap. Comparison is rune-based so
// multi-byte characters are never cut mid-rune.
func capText(s string, max int) string {
	if max <= 0 {
		return s
	}
	n := 0
	for i := range s { // rune index iteration
		if n == max {
			return s[:i] + truncMarker
		}
		n++
	}
	return s
}

// txt sanitizes a free-text field with a generous default cap.
func txt(s string) string { return capText(sanitizeText(s), MaxLineLen) }

// evidence sanitizes and caps untrusted evidence text.
func evidence(s string) string { return capText(sanitizeText(s), MaxEvidenceLen) }

// description sanitizes and caps untrusted finding descriptions.
func description(s string) string { return capText(sanitizeText(s), MaxDescriptionLen) }

// technical sanitizes and caps untrusted technical detail text.
func technical(s string) string { return capText(sanitizeText(s), MaxTechnicalLen) }

// title sanitizes and caps a finding title.
func title(s string) string { return capText(sanitizeText(s), MaxTitleLen) }

// pdfText converts sanitized text into the WinAnsi byte repertoire of the
// core PDF fonts: printable Latin-1 passes through unchanged, common
// typographic Unicode characters map to their WinAnsi bytes, everything
// else becomes '?'. Control characters are dropped as a final safety net.
func pdfText(s string) string {
	s = sanitizeText(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == '\v' || r == '\f':
			b.WriteByte(' ')
		case r >= 0x20 && r <= 0x7E: // printable ASCII
			b.WriteByte(byte(r))
		case r >= 0xA0 && r <= 0xFF: // Latin-1 supplement
			b.WriteByte(byte(r))
		default:
			if by, ok := cp1252Specials[r]; ok {
				b.WriteByte(by)
			} else if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
				// control: drop
			} else {
				b.WriteByte('?')
			}
		}
	}
	return b.String()
}

// slugify turns an arbitrary (possibly non-Latin) name into a lowercase
// ASCII slug safe for file and directory names. Non-ASCII runes (including
// emoji such as 🧪) collapse to separators. The result is never empty.
func slugify(s string) string {
	var b strings.Builder
	prevDash := true // suppress leading dashes
	for _, r := range strings.ToLower(s) {
		// Transliterate common Latin-1 accents so names like "Héllo" get
		// readable "hello-..." slugs instead of embedded dashes.
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r >= 0xE0 && r <= 0xE5:
			r = 'a'
		case r >= 0xE8 && r <= 0xEB:
			r = 'e'
		case r >= 0xEC && r <= 0xEF:
			r = 'i'
		case r >= 0xF2 && r <= 0xF6:
			r = 'o'
		case r >= 0xF9 && r <= 0xFC:
			r = 'u'
		case r == 0xE7:
			r = 'c'
		case r == 0xF1:
			r = 'n'
		case r == 0xFF:
			r = 'y'
		default:
			r = '-'
		}
		if r == '-' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "project"
	}
	return out
}

// fileSafe reduces an arbitrary string to characters that are safe inside a
// Content-Disposition filename and a ZIP entry name: [A-Za-z0-9._-].
func fileSafe(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
			prevDash = false
		case r == '-':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "report"
	}
	return out
}

// isPathSafe verifies that a stored file_path is a plain relative path that
// cannot escape the report directory.
func isPathSafe(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") ||
		strings.Contains(rel, "\x00") {
		return false
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// collapseWhitespace flattens runs of whitespace into single spaces — used
// for table cells that must stay on one visual line.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(sanitizeText(s)), " ")
}
