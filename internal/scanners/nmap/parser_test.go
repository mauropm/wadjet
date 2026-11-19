package nmap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

func TestParseFullFixture(t *testing.T) {
	res, err := Parse(fixture(t, "full.xml"))
	require.NoError(t, err)
	require.Len(t, res.Assets, 3, "two up hosts + one down host recorded as observations")

	byID := map[string]int{}
	for i, a := range res.Assets {
		byID[a.Identity] = i
	}

	// Host 1: 10.0.0.5 — full data.
	web, ok := byID["10.0.0.5"]
	require.True(t, ok)
	a := res.Assets[web]
	assert.Equal(t, "10.0.0.5", a.IPv4)
	assert.Equal(t, "00:1A:2B:3C:4D:5E", a.MAC)
	assert.Equal(t, []string{"web01.lab.example.com"}, a.Hostnames, "hostnames lowercased")
	assert.Equal(t, "Linux 5.10 - 5.16", a.OSName, "best osmatch by accuracy")
	assert.Equal(t, 97, a.OSAccuracy)
	require.Len(t, a.Ports, 3)
	assert.Equal(t, 22, a.Ports[0].Port)
	assert.Equal(t, "open", a.Ports[0].State)
	assert.Equal(t, "ssh", a.Ports[0].Service)
	assert.Equal(t, "OpenSSH", a.Ports[0].Product)
	assert.Equal(t, "8.9p1 Ubuntu 3ubuntu0.6", a.Ports[0].Version)
	assert.Equal(t, "Ubuntu Linux; protocol 2.0", a.Ports[0].ExtraInfo)
	assert.Equal(t, "filtered", a.Ports[2].State)

	// Info-only scripts must land in Extra, never findings.
	scripts, isMap := a.Extra["scripts"].(map[string]string)
	require.True(t, isMap, "script notes stored in Extra")
	assert.Contains(t, scripts, "tcp/443:http-title")
	assert.Contains(t, scripts, "tcp/22:ssh-hostkey")

	// ssl-enum-ciphers weak crypto → findings on port 443.
	var foundProtos, foundCiphers bool
	for _, f := range res.Findings {
		if f.Identity != "10.0.0.5" || f.Evidence.Script != "ssl-enum-ciphers" {
			continue
		}
		switch f.Title {
		case "Weak SSL/TLS cipher suites offered":
			foundCiphers = true
			assert.Equal(t, "medium", f.Severity)
			require.NotNil(t, f.Port)
			assert.Equal(t, 443, *f.Port)
		case "Obsolete SSL/TLS protocol enabled":
			foundProtos = true
			assert.Equal(t, "high", f.Severity)
		}
		assert.NotEmpty(t, f.Evidence.Output)
		assert.NotEmpty(t, f.Evidence.Raw)
	}
	assert.True(t, foundProtos, "SSLv?/old TLS detection")
	assert.True(t, foundCiphers, "RC4/3DES detection")
	// No fabricated CVEs.
	for _, f := range res.Findings {
		assert.Empty(t, f.CVSSScore, "CVSS must never be fabricated")
	}

	// Host 2: down host recorded with status.
	down, ok := byID["10.0.0.6"]
	require.True(t, ok)
	assert.Equal(t, "down", res.Assets[down].Extra["status"])

	// Host 3: identity = lowercased first hostname; hostscript in Extra.
	router, ok := byID["router-local"]
	require.True(t, ok)
	assert.Empty(t, res.Assets[router].Ports)
	scripts, isMap = res.Assets[router].Extra["scripts"].(map[string]string)
	require.True(t, isMap)
	assert.Contains(t, scripts, "host:smb-os-discovery")
}

func TestParseVulnFixture(t *testing.T) {
	res, err := Parse(fixture(t, "vulns.xml"))
	require.NoError(t, err)

	h10, h11 := -1, -1
	for i, a := range res.Assets {
		switch a.Identity {
		case "192.168.1.10":
			h10 = i
		case "192.168.1.11":
			h11 = i
		}
	}
	require.NotEqual(t, -1, h10)
	require.NotEqual(t, -1, h11)
	assert.Equal(t, "fe80::250:56ff:fe01:2", res.Assets[h10].IPv6)

	// Malformed attributes produce per-target errors, not a fatal parse.
	require.NotEmpty(t, res.Errors)
	var sawPortid, sawAccuracy bool
	for _, e := range res.Errors {
		if e.Target == "192.168.1.10" {
			switch {
			case containsStr(e.Error, "portid"):
				sawPortid = true
			case containsStr(e.Error, "accuracy"):
				sawAccuracy = true
			}
		}
	}
	assert.True(t, sawPortid, "malformed portid recorded")
	assert.True(t, sawAccuracy, "malformed osmatch accuracy recorded")
	assert.Equal(t, "Linux 4.4 real", res.Assets[h10].OSName, "valid osmatch survives bad sibling")

	// Curated findings for the vulnerable host.
	want := map[string]struct {
		severity string
		port     int
	}{
		"Anonymous FTP login permitted":      {"high", 21},
		"DNS zone transfer permitted":        {"high", 53},
		"Dangerous HTTP methods enabled":     {"medium", 80},
		"SSLv2 enabled on TLS port":          {"critical", 443},
		"Potential vulnerability detected by http-vuln-cve2021-41773": {"high", 80},
	}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		if f.Identity != "192.168.1.10" {
			continue
		}
		exp, ok := want[f.Title]
		require.True(t, ok, "unexpected finding %q", f.Title)
		assert.Equal(t, exp.severity, f.Severity, f.Title)
		require.NotNil(t, f.Port, f.Title)
		assert.Equal(t, exp.port, *f.Port, f.Title)
		seen[f.Title] = true
	}
	for title := range want {
		assert.True(t, seen[title], "missing finding: %s", title)
	}

	// CVE extracted from literal output text only.
	var cveFound []string
	for _, f := range res.Findings {
		cveFound = append(cveFound, f.CVEs...)
	}
	assert.Contains(t, cveFound, "CVE-2021-41773")

	// Host .11: State: SAFE vuln script must NOT create a finding even
	// though a CVE id appears in its reference text.
	for _, f := range res.Findings {
		if f.Identity == "192.168.1.11" {
			t.Fatalf("SAFE vuln script must not produce findings, got %q", f.Title)
		}
	}
	a11 := res.Assets[h11]
	notes, ok := a11.Extra["scripts"].(map[string]string)
	require.True(t, ok)
	assert.Contains(t, notes, "tcp/80:http-vuln-cve2017-5638")

	// Unmatched script stays informational.
	notes10, _ := res.Assets[h10].Extra["scripts"].(map[string]string)
	assert.Contains(t, notes10, "host:firewalk-enum")
}

func TestParseEdgeCases(t *testing.T) {
	cases := []struct{ name, xml, wantErr string }{
		{"empty", "", "empty output"},
		{"garbage", "\x00\x01not xml at all", "malformed XML"},
		{"wrong root", `<foo><host/></foo>`, "not an nmaprun"},
		{"host without identity",
			`<nmaprun><host><status state="up"/></host></nmaprun>`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Parse([]byte(c.xml))
			if c.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Empty(t, res.Assets)
			require.NotEmpty(t, res.Errors, "identityless host recorded as error")
		})
	}
}

func TestParseRawOutputPreserved(t *testing.T) {
	raw := fixture(t, "full.xml")
	res, err := Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, raw, res.RawOutput, "raw XML bytes preserved verbatim")
}

func TestNormalizeState(t *testing.T) {
	assert.Equal(t, "open", normalizeState("open"))
	assert.Equal(t, "closed", normalizeState(" closed "))
	assert.Equal(t, "open", normalizeState("open|filtered"))
	assert.Equal(t, "unknown", normalizeState("weird"))
	assert.Equal(t, "unknown", normalizeState(""))
}

func TestScriptEvidencePreserved(t *testing.T) {
	res, err := Parse(fixture(t, "vulns.xml"))
	require.NoError(t, err)
	for _, f := range res.Findings {
		require.NotEmpty(t, f.Evidence.Script)
		require.NotEmpty(t, f.Evidence.Output)
		var sc nmapScript
		require.NoError(t, json.Unmarshal(f.Evidence.Raw, &sc), "Raw preserves the script element")
		assert.Equal(t, f.Evidence.Script, sc.ID)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
