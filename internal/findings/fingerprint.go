// Package findings ingests normalized scanner results and serves the finding
// inventory: deduplication by fingerprint, append-only detection history,
// analyst status workflow and project-wide queries.
//
// Ownership: Agent 3.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/mauropm/wadjet/internal/scanners"
)

// fingerprintLength is the number of hex characters kept from the digest. 128
// bits per (project, asset) scope is far beyond the number of findings a
// project holds, so collisions are not a practical concern while the key stays
// short enough to index and display.
const fingerprintLength = 32

// fingerprintCore is the canonical projection a fingerprint is computed from.
//
// The field order below IS the canonical order: encoding/json marshals struct
// fields in declaration order, which makes the digest reproducible across
// processes and Go versions. Never reorder these fields or add a volatile one
// (timestamps, evidence text, counters) — every existing finding would
// silently fork into a second row the next time a scanner reported it.
type fingerprintCore struct {
	Title    string `json:"title"`
	Scanner  string `json:"scanner"`
	Port     *int   `json:"port"`
	Protocol string `json:"protocol"`
}

// NormalizeFindingText lower-cases, trims and collapses every run of
// whitespace into a single space, so that "  TLS   Certificate EXPIRES  " and
// "tls certificate expires" are the same issue.
func NormalizeFindingText(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// FindingFingerprint returns the stable deduplication key of a finding: the
// first 32 hex characters of the SHA-256 digest of the canonical JSON of
// {title, scanner, port, protocol} after normalization.
//
// What is deliberately excluded, and why:
//
//   - asset identity: identity is already the asset scope — the unique key is
//     (project_id, asset_id, fingerprint), so including it would only make the
//     digest harder to reason about;
//   - evidence text, raw payloads and timestamps: they change between runs of
//     the same scanner against the same issue and would create duplicates;
//   - description, remediation, severity, CVSS, CVEs, service: they are
//     enriched over time, and a finding must survive those edits;
//   - protocol is normalised ("TCP" == "tcp"), a nil port stays distinct from
//     port 0, and a nil port plus "tcp" is distinct from a nil port with no
//     protocol.
//
// Consequences that the tests pin down: cosmetic title changes (case,
// whitespace) keep the fingerprint; changing port, protocol, scanner or title
// wording produces a different one.
func FindingFingerprint(title, scanner string, port *int, protocol string) string {
	core := fingerprintCore{
		Title:    NormalizeFindingText(title),
		Scanner:  NormalizeFindingText(scanner),
		Protocol: NormalizeFindingText(protocol),
	}
	if port != nil && *port > 0 {
		p := *port
		core.Port = &p
	}
	canonical, err := json.Marshal(core)
	if err != nil {
		// json.Marshal cannot fail for this shape; fall back to a
		// concatenation so ingestion never aborts over a fingerprint.
		canonical = []byte(core.Title + "|" + core.Scanner + "|" + core.Protocol)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])[:fingerprintLength]
}

// FindingFingerprintFor derives the fingerprint of a scanner result. The
// scanner name comes from the execution, not from the payload: a scanner must
// not be able to forge its identity in the dedup key. See FindingFingerprint
// for the excluded-field rationale.
func FindingFingerprintFor(f scanners.FindingResult, scannerName string) string {
	return FindingFingerprint(f.Title, scannerName, f.Port, f.Protocol)
}
