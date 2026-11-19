package nativeprobe

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/scanners"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		in    string
		want  []int
		valid bool
	}{
		{"22", []int{22}, true},
		{"22,80,443", []int{22, 80, 443}, true},
		{"79-81", []int{79, 80, 81}, true},
		{"80,80,80", []int{80}, true},
		{"1-3,3-5", []int{1, 2, 3, 4, 5}, true},
		{"", nil, false},
		{"0", nil, false},
		{"65536", nil, false},
		{"9000-8000", nil, false},
		{"80; rm -rf /", nil, false},
		{"--all", nil, false},
		{"$(id)", nil, false},
		{"80 443", nil, false},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.in), func(t *testing.T) {
			got, err := ParsePorts(tc.in)
			if tc.valid {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestParsePortsCap(t *testing.T) {
	_, err := ParsePorts("1-4097")
	require.Error(t, err, "must refuse more than maxProbesPerTarget ports")
	_, err = ParsePorts("1-4096")
	require.NoError(t, err)
}

func TestValidateConfig(t *testing.T) {
	s := New()
	require.NoError(t, s.ValidateConfig(scanners.ScannerConfig{}))
	require.NoError(t, s.ValidateConfig(scanners.ScannerConfig{"ports": "22,80", "connect_timeout_ms": 500.0, "concurrency": 8.0}))
	require.Error(t, s.ValidateConfig(scanners.ScannerConfig{"ports": "99999"}))
	require.Error(t, s.ValidateConfig(scanners.ScannerConfig{"ports": "80; id"}))
	require.Error(t, s.ValidateConfig(scanners.ScannerConfig{"bogus": true}))
}

func TestValidateTarget(t *testing.T) {
	s := New()
	require.NoError(t, s.ValidateTarget(scanners.Target{Raw: "127.0.0.1", Type: "ip"}))
	require.NoError(t, s.ValidateTarget(scanners.Target{Raw: "::1", Type: "ipv6"}))
	require.NoError(t, s.ValidateTarget(scanners.Target{Raw: "localhost", Type: "hostname"}))
	require.Error(t, s.ValidateTarget(scanners.Target{Raw: "10.0.0.0/24", Type: "cidr"}))
	require.Error(t, s.ValidateTarget(scanners.Target{Raw: "http://x", Type: "url"}))
	require.Error(t, s.ValidateTarget(scanners.Target{Raw: "", Type: "ip"}))
}

// listenOn starts a TCP listener on loopback and returns its port.
func listenOn(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestExecuteProbes(t *testing.T) {
	openPort := listenOn(t)
	// A closed port: bind then release; loopback gives immediate RST.
	closed := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		p := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		return p
	}()

	s := New()
	res, err := s.Execute(context.Background(), scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		Config:  scanners.ScannerConfig{"ports": fmt.Sprintf("%d,%d", openPort, closed)},
		WorkDir: t.TempDir(),
	})
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)
	obs := res.Assets[0]
	assert.Equal(t, "127.0.0.1", obs.Identity)
	assert.Equal(t, "127.0.0.1", obs.IPv4)

	states := map[int]string{}
	for _, p := range obs.Ports {
		states[p.Port] = p.State
	}
	assert.Equal(t, "open", states[openPort])
	assert.Equal(t, "closed", states[closed])
	assert.Empty(t, res.Findings, "connect probes must never emit findings")
}

func TestExecuteHostnameResolution(t *testing.T) {
	s := New()
	res, err := s.Execute(context.Background(), scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "localhost", Type: "hostname"}},
		Config:  scanners.ScannerConfig{"ports": "65500"}, // nothing listening
		WorkDir: t.TempDir(),
	})
	require.NoError(t, err)
	// localhost resolves; probes report closed (or empty on exotic stacks).
	for _, e := range res.Errors {
		require.NotContains(t, e.Error, "resolve", "localhost must resolve: %v", e)
	}
}

func TestExecuteBadHostname(t *testing.T) {
	s := New()
	res, err := s.Execute(context.Background(), scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "definitely.invalid.tld.wadjet-test", Type: "hostname"}},
		Config:  scanners.ScannerConfig{"ports": "80"},
		WorkDir: t.TempDir(),
	})
	require.NoError(t, err, "per-target failures are recorded, not fatal")
	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0].Error, "resolve")
}

func TestExecuteCancellation(t *testing.T) {
	s := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Execute(ctx, scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "203.0.113.254", Type: "ip"}}, // TEST-NET-3, blackhole
		Config: scanners.ScannerConfig{
			"ports":              "1-600",
			"connect_timeout_ms": 5000.0,
		},
		WorkDir: t.TempDir(),
	})
	require.Error(t, err, "cancelled context must abort")
	assert.Contains(t, err.Error(), "context canceled")
}

func TestContract(t *testing.T) {
	var s scanners.Scanner = New()
	assert.Equal(t, "nativeprobe", s.Name())
	assert.Equal(t, "builtin", s.Version())
	assert.NotEmpty(t, s.Description())
	assert.Equal(t, []scanners.Capability{scanners.CapHostDiscovery, scanners.CapPortDiscovery}, s.Capabilities())
}
