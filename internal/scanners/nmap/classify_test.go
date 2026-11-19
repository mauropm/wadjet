package nmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/scanners"
)

func TestClassifyScript(t *testing.T) {
	port := func(p int, proto, svc string) *scanners.PortObservation {
		return &scanners.PortObservation{Port: p, Protocol: proto, State: "open", Service: svc}
	}
	tests := []struct {
		name       string
		script     nmapScript
		port       *scanners.PortObservation
		wantTitles []string // exact titles expected (empty = expect no findings)
		wantSev    []string
		wantCVEs   []string
	}{
		{
			name:       "ssl-enum-ciphers weak ciphers",
			port:       port(443, "tcp", "ssl/http"),
			script:     nmapScript{ID: "ssl-enum-ciphers", Output: "  TLSv1.2: \n    ciphers: \n      TLS_RSA_WITH_RC4_128_SHA (rsa_2048, rc4, 128)"},
			wantTitles: []string{"Weak SSL/TLS cipher suites offered"},
			wantSev:    []string{"medium"},
		},
		{
			name:       "ssl-enum-ciphers obsolete protocol",
			port:       port(443, "tcp", "ssl/http"),
			script:     nmapScript{ID: "ssl-enum-ciphers", Output: "  SSLv3: \n    ciphers: \n      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa_2048, 3des, cbc, 112)"},
			wantTitles: []string{"Obsolete SSL/TLS protocol enabled", "Weak SSL/TLS cipher suites offered"},
			wantSev:    []string{"high", "medium"},
		},
		{
			name:       "ssl-enum-ciphers clean",
			port:       port(443, "tcp", "ssl/http"),
			script:     nmapScript{ID: "ssl-enum-ciphers", Output: "  TLSv1.2: \n    ciphers: \n      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (rsa_2048, ecdh_256, aes-256-gcm, 256)"},
			wantTitles: nil,
		},
		{
			name:       "sslv2 supported",
			port:       port(443, "tcp", "https"),
			script:     nmapScript{ID: "sslv2", Output: "  SSLv2: \n    SSLv2 supported: \n      ciphers: \n        SSL2_RC4_128_WITH_MD5"},
			wantTitles: []string{"SSLv2 enabled on TLS port"},
			wantSev:    []string{"critical"},
		},
		{
			name:       "sslv2 not supported",
			port:       port(443, "tcp", "https"),
			script:     nmapScript{ID: "sslv2", Output: "  SSLv2: \n    not supported"},
			wantTitles: nil,
		},
		{
			name:       "ssh-hostkey weak",
			port:       port(22, "tcp", "ssh"),
			script:     nmapScript{ID: "ssh-hostkey", Output: "  1024 ssh-dss SHA256:abc (DSA)"},
			wantTitles: []string{"Weak SSH host key"},
			wantSev:    []string{"low"},
		},
		{
			name:       "ssh-hostkey strong",
			port:       port(22, "tcp", "ssh"),
			script:     nmapScript{ID: "ssh-hostkey", Output: "  4096 rsa SHA256:abc (RSA)\n  256 ssh-ed25519 SHA256:def (ED25519)"},
			wantTitles: nil,
		},
		{
			name:       "ftp-anon allowed",
			port:       port(21, "tcp", "ftp"),
			script:     nmapScript{ID: "ftp-anon", Output: "  Anonymous FTP login allowed (FTP code 230)"},
			wantTitles: []string{"Anonymous FTP login permitted"},
			wantSev:    []string{"high"},
		},
		{
			name:       "ftp-anon denied",
			port:       port(21, "tcp", "ftp"),
			script:     nmapScript{ID: "ftp-anon", Output: "  FTP server requires a username"},
			wantTitles: nil,
		},
		{
			name:       "http-methods dangerous",
			port:       port(80, "tcp", "http"),
			script:     nmapScript{ID: "http-methods", Output: "  Supported Methods: GET HEAD POST PUT DELETE TRACE"},
			wantTitles: []string{"Dangerous HTTP methods enabled"},
			wantSev:    []string{"medium"},
		},
		{
			name:       "http-methods safe",
			port:       port(80, "tcp", "http"),
			script:     nmapScript{ID: "http-methods", Output: "  Supported Methods: GET HEAD POST OPTIONS"},
			wantTitles: nil,
		},
		{
			name:       "dns-zone-transfer",
			port:       port(53, "tcp", "domain"),
			script:     nmapScript{ID: "dns-zone-transfer", Output: "  Zone transferred: 37 records"},
			wantTitles: []string{"DNS zone transfer permitted"},
			wantSev:    []string{"high"},
		},
		{
			name:       "telnet exposed",
			port:       port(23, "tcp", "telnet"),
			script:     nmapScript{ID: "telnet-echo", Output: "  Echo service is on"},
			wantTitles: []string{"Telnet service exposed"},
			wantSev:    []string{"medium"},
		},
		{
			name: "vuln script positive with CVE",
			port: port(80, "tcp", "http"),
			script: nmapScript{ID: "http-vuln-cve2021-41773",
				Output: "  State: VULNERABLE\n  A path traversal flaw (CVE-2021-41773) allows reading files"},
			wantTitles: []string{"Potential vulnerability detected by http-vuln-cve2021-41773"},
			wantSev:    []string{"high"},
			wantCVEs:   []string{"CVE-2021-41773"},
		},
		{
			name: "vuln script safe result with CVE mention",
			port: port(80, "tcp", "http"),
			script: nmapScript{ID: "http-vuln-cve2017-5638",
				Output: "  State: SAFE\n  Research: cve.mitre.org #CVE-2017-5638"},
			wantTitles: nil,
		},
		{
			name:       "vuln script no vulns",
			port:       port(80, "tcp", "http"),
			script:     nmapScript{ID: "http-vuln-cve2017-5638", Output: "  no vulns were found"},
			wantTitles: nil,
		},
		{
			name:       "generic vuln keyword in arbitrary script",
			port:       port(80, "tcp", "http"),
			script:     nmapScript{ID: "http-sql-injection", Output: "  Possible SQL injection at /search?q="},
			wantTitles: []string{"Potential vulnerability detected by http-sql-injection"},
			wantSev:    []string{"high"},
		},
		// Banner scripts: never findings.
		{name: "http-title banner", port: port(80, "tcp", "http"), script: nmapScript{ID: "http-title", Output: "  Site title: X"}, wantTitles: nil},
		{name: "http-server-header banner", port: port(80, "tcp", "http"), script: nmapScript{ID: "http-server-header", Output: "  Apache/2.4.49"}, wantTitles: nil},
		{name: "unknown script informational", port: nil, script: nmapScript{ID: "mystery-probe", Output: "  something interesting"}, wantTitles: nil},
		{name: "empty id ignored", port: nil, script: nmapScript{ID: "", Output: "State: VULNERABLE"}, wantTitles: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := classifyScript("10.0.0.1", tc.port, tc.script)
			var titles, sevs, cves []string
			for _, f := range fs {
				titles = append(titles, f.Title)
				sevs = append(sevs, f.Severity)
				cves = append(cves, f.CVEs...)
				assert.Equal(t, "10.0.0.1", f.Identity)
				assert.Contains(t, []string{"critical", "high", "medium", "low", "info"}, f.Severity)
				if tc.port != nil {
					require.NotNil(t, f.Port, "port-level script finding must carry port")
					assert.Equal(t, tc.port.Port, *f.Port)
					assert.Equal(t, tc.port.Protocol, f.Protocol)
				}
			}
			assert.ElementsMatch(t, tc.wantTitles, titles)
			assert.ElementsMatch(t, tc.wantSev, sevs)
			assert.ElementsMatch(t, tc.wantCVEs, cves)
		})
	}
}

func TestClassifyNeverFabricatesCVSS(t *testing.T) {
	scripts := []nmapScript{
		{ID: "ssl-enum-ciphers", Output: "SSLv3 TLS_RSA_WITH_RC4_128_MD5"},
		{ID: "http-vuln-cve2021-41773", Output: "State: VULNERABLE CVE-2021-41773"},
		{ID: "ftp-anon", Output: "Anonymous FTP login allowed"},
	}
	for _, sc := range scripts {
		for _, f := range classifyScript("h", nil, sc) {
			assert.Nil(t, f.CVSSScore, "CVSS score fabricated for %s", sc.ID)
		}
	}
}

func TestExtractCVEsDedupesAndUpperCases(t *testing.T) {
	out := "cve-2021-41773 and CVE-2021-41773 and CVE-2017-5638 plus cve-2999-1 malformed cve-2021-1"
	cves := extractCVEs(out)
	assert.Equal(t, []string{"CVE-2021-41773", "CVE-2017-5638"}, cves)
}

func TestInfoOnlyScriptsNeverFindings(t *testing.T) {
	for id := range infoOnlyScripts {
		fs := classifyScript("h", &scanners.PortObservation{Port: 80, Protocol: "tcp"},
			nmapScript{ID: id, Output: "State: VULNERABLE CVE-2020-0001 anonymous ftp login allowed"})
		// Info-only scripts short-circuit before the generic vuln heuristic.
		assert.Empty(t, fs, "info-only script %s must never produce findings", id)
	}
}
