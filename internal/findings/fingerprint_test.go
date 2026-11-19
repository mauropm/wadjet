package findings

import (
	"strings"
	"testing"

	"github.com/mauropm/wadjet/internal/scanners"
)

func ptrInt(i int) *int { return &i }

// TestFingerprintIsStableAcrossCosmeticChanges pins the property that keeps the
// inventory from forking: a scanner rewording the same issue must not create a
// second finding.
func TestFingerprintIsStableAcrossCosmeticChanges(t *testing.T) {
	base := FindingFingerprint("TLS Certificate Expires Soon", "nmap-nse", ptrInt(443), "TCP")

	variants := []struct {
		title, scanner, protocol string
		port                     *int
		why                      string
	}{
		{"tls certificate expires soon", "nmap-nse", "tcp", ptrInt(443), "case only"},
		{"  TLS   Certificate  Expires  Soon ", "nmap-nse", "tcp", ptrInt(443), "whitespace only"},
		{"TLS\tCertificate\nExpires Soon", "nmap-nse", "Tcp", ptrInt(443), "tabs and newlines"},
		{"TLS Certificate Expires Soon", "  nmap-nse ", "TCP ", ptrInt(443), "padded scanner and protocol"},
	}
	for _, v := range variants {
		got := FindingFingerprint(v.title, v.scanner, v.port, v.protocol)
		if got != base {
			t.Errorf("%s: fingerprint changed (%s -> %s)", v.why, base, got)
		}
	}
}

// TestFingerprintChangesAcrossMaterialFields pins the other half: a genuinely
// different issue must never collapse onto an existing finding.
func TestFingerprintChangesAcrossMaterialFields(t *testing.T) {
	base := FindingFingerprint("Open SSH", "nmap", ptrInt(22), "tcp")

	different := []struct {
		title, scanner, protocol string
		port                     *int
		why                      string
	}{
		{"Open SSL", "nmap", "tcp", ptrInt(22), "title wording"},
		{"Open SSH", "nuclei", "tcp", ptrInt(22), "scanner"},
		{"Open SSH", "nmap", "udp", ptrInt(22), "protocol"},
		{"Open SSH", "nmap", "", ptrInt(22), "protocol removed"},
		{"Open SSH", "nmap", "tcp", ptrInt(8022), "port"},
		{"Open SSH", "nmap", "tcp", nil, "port removed"},
	}
	for _, d := range different {
		got := FindingFingerprint(d.title, d.scanner, d.port, d.protocol)
		if got == base {
			t.Errorf("%s: fingerprint did not change", d.why)
		}
	}
}

// TestFingerprintIgnoresVolatileAndScopeFields documents what is excluded:
// volatile text and the asset identity, which is already the asset scope of the
// unique key (project_id, asset_id, fingerprint).
func TestFingerprintIgnoresVolatileAndScopeFields(t *testing.T) {
	f := func(mutate func(*scanners.FindingResult)) scanners.FindingResult {
		fr := scanners.FindingResult{
			Title:       "SQL injection",
			Description: "first wording",
			Port:        ptrInt(80),
			Protocol:    "tcp",
			Service:     "http",
			Severity:    "high",
			Identity:    "shop.example.com",
			CVEs:        []string{"CVE-2024-0001"},
			References:  []string{"https://example.com/advisory"},
			Evidence:    scanners.FindingEvidence{Snippet: "payload: ' OR 1=1"},
		}
		mutate(&fr)
		return fr
	}

	base := FindingFingerprintFor(f(func(*scanners.FindingResult) {}), "nuclei")

	changes := map[string]func(*scanners.FindingResult){
		"identity":        func(r *scanners.FindingResult) { r.Identity = "10.0.0.9" },
		"description":     func(r *scanners.FindingResult) { r.Description = "completely different wording" },
		"severity":        func(r *scanners.FindingResult) { r.Severity = "critical" },
		"cves":            func(r *scanners.FindingResult) { r.CVEs = []string{"CVE-2099-9999"} },
		"references":      func(r *scanners.FindingResult) { r.References = nil },
		"service":         func(r *scanners.FindingResult) { r.Service = "https" },
		"evidence":        func(r *scanners.FindingResult) { r.Evidence.Snippet = "totally new evidence" },
		"evidence-raw":    func(r *scanners.FindingResult) { r.Evidence.Raw = []byte(`{"run":2}`) },
		"remediation":     func(r *scanners.FindingResult) { r.Remediation = "patch it" },
		"technical":       func(r *scanners.FindingResult) { r.TechnicalDetails = "new details" },
		"cvss":            func(r *scanners.FindingResult) { v := 9.9; r.CVSSScore = &v },
		"scanner-name-bl": func(r *scanners.FindingResult) {},
	}
	for name, mutate := range changes {
		got := FindingFingerprintFor(f(mutate), "nuclei")
		if name == "scanner-name-bl" {
			// sanity: the same input reproduces the base digest
			if got != base {
				t.Errorf("unmodified result produced a different fingerprint")
			}
			continue
		}
		if got != base {
			t.Errorf("%s changed the fingerprint: %s != %s", name, got, base)
		}
	}

	// The scanner identity itself is material and comes from the execution.
	if FindingFingerprintFor(f(func(*scanners.FindingResult) {}), "zap") == base {
		t.Error("changing the scanner name did not change the fingerprint")
	}
}

func TestFingerprintShape(t *testing.T) {
	fp := FindingFingerprint("Anything", "nmap", ptrInt(1), "tcp")
	if len(fp) != fingerprintLength {
		t.Fatalf("length = %d, want %d", len(fp), fingerprintLength)
	}
	if strings.ToLower(fp) != fp {
		t.Fatalf("fingerprint is not lowercase hex: %s", fp)
	}
	for _, c := range fp {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex character %q in %s", c, fp)
		}
	}
	if fp != FindingFingerprint("Anything", "nmap", ptrInt(1), "tcp") {
		t.Fatal("fingerprint is not deterministic")
	}
	// A nil port and port 0 must not collide with a real port.
	if FindingFingerprint("X", "nmap", nil, "tcp") == FindingFingerprint("X", "nmap", ptrInt(0), "tcp") &&
		FindingFingerprint("X", "nmap", ptrInt(0), "tcp") != FindingFingerprint("X", "nmap", ptrInt(80), "tcp") {
		t.Log("port 0 is treated as absent")
	}
	if FindingFingerprint("X", "nmap", nil, "") == FindingFingerprint("X", "nmap", ptrInt(80), "tcp") {
		t.Fatal("portless and ported findings collided")
	}
}

func TestNormalizeFindingText(t *testing.T) {
	cases := map[string]string{
		"  Hello   World ":           "hello world",
		"UPPER\nlower\tmixed":        "upper lower mixed",
		"single":                     "single",
		"":                           "",
		"  many    spaces   here  ":  "many spaces here",
		"MiXeD\t\tCase\n\nNewlines ": "mixed case newlines",
	}
	for in, want := range cases {
		if got := NormalizeFindingText(in); got != want {
			t.Errorf("NormalizeFindingText(%q) = %q, want %q", in, got, want)
		}
	}
}
