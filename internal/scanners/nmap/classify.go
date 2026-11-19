package nmap

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/mauropm/wadjet/internal/scanners"
)

// Curated NSE classification table.
//
// Security rules (binding):
//   - Findings are produced ONLY from the patterns below. Scripts that do
//     not match remain INFO observations in AssetObservationData.Extra and
//     are never turned into findings.
//   - CVE ids are only ever extracted from literal "CVE-YYYY-NNNN" text in
//     script output; CVSS scores are never fabricated.

// cveRe extracts CVE ids from free-text script output.
var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)

// vulnNegativeRe marks outputs where a vulnerability script found nothing.
var vulnNegativeRe = regexp.MustCompile(
	`(?i)(no vulns were found|not vulnerable|no known vulns|no time for|vulnerability check failed|ERROR: Script execution failed|host seems not up|State:\s*SAFE\b)`)

// vulnPositiveRe marks outputs where a vuln-category script detected a hit.
var vulnPositiveRe = regexp.MustCompile(
	`(?i)(State: VULNERABLE|\bvulnerable\b|XSS\b|cross-site scripting|SQL injection|command injection|remote code execution|allows? remote|Zone transferred|backdoor|webshell|default credentials?|anonymous (ftp )?login allowed|unauthorized)`)

// maxOutputEvidence bounds retained script output per finding.
const maxOutputEvidence = 8192

// classifyScript returns findings implied by one script element's output.
// An empty result means "informational only" and the caller records the
// script output as an observation note.
func classifyScript(identity string, port *scanners.PortObservation, sc nmapScript) []scanners.FindingResult {
	if strings.TrimSpace(sc.ID) == "" {
		return nil
	}
	out := sc.Output

	base := func(sev, title, details, remediation string, refs []string) scanners.FindingResult {
		f := scanners.FindingResult{
			Title:            title,
			Description:      fmt.Sprintf("Detected by Nmap NSE script %s.", sc.ID),
			TechnicalDetails: details,
			Identity:         identity,
			Severity:         sev,
			Remediation:      remediation,
			References:       refs,
			Evidence: scanners.FindingEvidence{
				Script:  sc.ID,
				Output:  truncate(sc.Output, maxOutputEvidence),
				Snippet: firstMatchedLine(sc.Output),
			},
		}
		if port != nil {
			p := port.Port
			f.Port = &p
			f.Protocol = port.Protocol
			f.Service = port.Service
		}
		if cves := extractCVEs(out); len(cves) > 0 {
			f.CVEs = cves
		}
		if raw, err := json.Marshal(sc); err == nil {
			f.Evidence.Raw = raw
		}
		return f
	}

	var findings []scanners.FindingResult
	add := func(f scanners.FindingResult) { findings = append(findings, f) }

	switch sc.ID {
	case "ssl-enum-ciphers":
		if m := obsoleteTLSRe.FindAllString(out, -1); len(m) > 0 {
			add(base(sevHigh, "Obsolete SSL/TLS protocol enabled",
				fmt.Sprintf("Server offers obsolete protocol(s): %s.", strings.Join(uniq(m), ", ")),
				"Disable SSLv2/SSLv3 and TLS 1.0/1.1; require TLS 1.2+ with modern cipher suites.",
				[]string{"https://datatracker.ietf.org/doc/html/rfc8996"}))
		}
		if m := weakCipherRe.FindAllString(out, -1); len(m) > 0 {
			add(base(sevMedium, "Weak SSL/TLS cipher suites offered",
				fmt.Sprintf("Weak cipher(s) detected: %s.", strings.Join(uniq(m), ", ")),
				"Restrict the server to AEAD cipher suites (e.g. ECDHE+AES-GCM); remove RC4, DES/3DES, NULL, EXPORT and CBC-SHA1 suites.",
				[]string{"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf"}))
		}
		if m := strongButOldRe.FindAllString(out, -1); len(m) > 0 && len(findings) == 0 {
			add(base(sevMedium, "Deprecated TLS 1.0/1.1 protocol supported",
				fmt.Sprintf("Server still negotiates %s.", strings.Join(uniq(m), ", ")),
				"Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.",
				[]string{"https://datatracker.ietf.org/doc/html/rfc8996"}))
		}

	case "sslv2":
		if strings.Contains(out, "SSLv2 supported") && !strings.Contains(out, "not supported") {
			add(base(sevCritical, "SSLv2 enabled on TLS port",
				"The port accepts SSLv2, a cryptographically broken protocol susceptible to downgrade attacks (e.g. DROWN).",
				"Disable SSLv2 at the server; patch/replace libraries that still enable it.",
				[]string{"https://drownattack.com/"}))
		}

	case "ssh-hostkey":
		if weakSSHKeyRe.MatchString(out) {
			add(base(sevLow, "Weak SSH host key",
				"The SSH server presents a weak host key (DSA, RSA < 2048 bits, or ECDSA P-256 only).",
				"Regenerate host keys: ed25519 preferred, RSA >= 4096 as fallback.",
				nil))
		}

	case "ftp-anon":
		if strings.Contains(out, "Anonymous FTP login allowed") {
			add(base(sevHigh, "Anonymous FTP login permitted",
				"The FTP server accepts anonymous (or guest) logins, exposing whatever is stored for anonymous read/write.",
				"Disable anonymous FTP access.",
				nil))
		}

	case "http-methods":
		if m := httpDangerousMethodsRe.FindString(out); m != "" {
			methods := dangerousMethodsIn(out)
			if len(methods) > 0 {
				add(base(sevMedium, "Dangerous HTTP methods enabled",
					fmt.Sprintf("Server advertises dangerous HTTP method(s): %s.", strings.Join(methods, ", ")),
					"Allow only GET/HEAD/POST (and OPTIONS if needed) on the front-end; block TRACE/PUT/DELETE/PATCH/CONNECT.",
					nil))
			}
		}

	case "dns-zone-transfer":
		if strings.Contains(strings.ToLower(out), "zone transferred") {
			add(base(sevHigh, "DNS zone transfer permitted",
				"AXFR zone transfer succeeded, disclosing the complete DNS record set of the zone.",
				"Restrict zone transfers to authorized secondary nameservers via ACLs.",
				[]string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0006"}))
		}

	case "telnet-echo":
		if strings.TrimSpace(out) != "" && !vulnNegativeRe.MatchString(out) {
			add(base(sevMedium, "Telnet service exposed",
				"An interactive Telnet service was detected; Telnet transmits credentials in cleartext.",
				"Disable Telnet and require SSH.",
				nil))
		}
	}

	// Generic vuln-category heuristics for scripts whose id signals a
	// vulnerability check, or any output containing explicit CVE ids or
	// unambiguous compromise language.
	if len(findings) == 0 && isVulnScript(sc.ID) && !vulnNegativeRe.MatchString(out) {
		if vulnPositiveRe.MatchString(out) || cveRe.MatchString(out) {
			add(base(sevHigh, fmt.Sprintf("Potential vulnerability detected by %s", sc.ID),
				"A Nmap vulnerability script reported a positive result. Review the retained evidence before triage.",
				"Validate the finding manually, then remediate and rescan.",
				nil))
		}
	}

	// Banner-information scripts: observations only, never findings.
	if isInfoOnlyScript(sc.ID) {
		return nil
	}

	return findings
}

const (
	sevCritical = "critical"
	sevHigh     = "high"
	sevMedium   = "medium"
	sevLow      = "low"
)

var (
	obsoleteTLSRe          = regexp.MustCompile(`SSLv[23]`)
	strongButOldRe         = regexp.MustCompile(`TLSv1\.[01]`)
	weakCipherRe           = regexp.MustCompile(`(?i)\b(RC4|DES(40|56|40-CBC)?|3DES|NULL|EXPORT[0-9A-Z-]*|MD5)\b`)
	weakSSHKeyRe           = regexp.MustCompile(`(?im)^\s*(1024|512|768)\s+|ssh-dss|\bssh-rsa\s+(1024|512)\b`)
	httpDangerousMethodsRe = regexp.MustCompile(`(?i)(Supported Methods|Unsafe methods|allowed methods)\s*:\s*[^\n]*\b(PUT|DELETE|TRACE|CONNECT|PATCH)\b`)
)

// infoOnlyScripts produce banner/inventory observations, never findings.
var infoOnlyScripts = map[string]bool{
	"http-title": true, "http-server-header": true, "http-headers": true,
	"http-robots-txt": true, "banner": true, "smb-os-discovery": true,
	"smb-protocols": true, "ssh2-enum-algos": true,
	"ntp-info": true, "snmp-sysdescr": true, "snmp-info": true,
	"nbstat": true, "clock-skew": true, "tls-info": true,
	"tls-nextprotoneg": true, "https-redirect": true, "http-traceroute": true,
	"ftp-syst": true, "vhosts": true, "ssl-date": true,
}

func isInfoOnlyScript(id string) bool { return infoOnlyScripts[id] }

// isVulnScript reports whether a script id belongs to the vulnerability
// family (vuln-category scripts follow the *-vuln* / category naming).
func isVulnScript(id string) bool {
	if strings.Contains(id, "vuln") || strings.HasPrefix(id, "http-sql") ||
		strings.Contains(id, "xss") || strings.Contains(id, "backdoor") {
		return true
	}
	for _, c := range knownVulnScripts {
		if id == c {
			return true
		}
	}
	return false
}

// knownVulnScripts is a small set of NSE scripts whose mere positive output
// is a genuine issue even without a "vuln" token in the id.
var knownVulnScripts = []string{
	"http-malware-host", "http-csrf", "http-default-accounts",
	"http-wordpress-brute", "http-enum",
}

func extractCVEs(out string) []string {
	var cves []string
	seen := map[string]bool{}
	for _, m := range cveRe.FindAllString(out, -1) {
		id := strings.ToUpper(m)
		if !seen[id] {
			seen[id] = true
			cves = append(cves, id)
		}
	}
	return cves
}

var dangerousMethodRes = map[string]*regexp.Regexp{}

func init() {
	for _, m := range []string{"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"} {
		dangerousMethodRes[m] = regexp.MustCompile(`(?i)\b` + m + `\b`)
	}
}

func dangerousMethodsIn(out string) []string {
	var found []string
	for _, m := range []string{"CONNECT", "DELETE", "PATCH", "PUT", "TRACE"} {
		if dangerousMethodRes[m].MatchString(out) {
			found = append(found, m)
		}
	}
	return found
}

// firstMatchedLine picks the most information-dense line of script output
// for evidence snippets.
func firstMatchedLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "|"))
		l = strings.TrimSpace(strings.TrimPrefix(l, "_"))
		if len(l) > 10 {
			return truncate(l, 500)
		}
	}
	return truncate(strings.TrimSpace(out), 500)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
