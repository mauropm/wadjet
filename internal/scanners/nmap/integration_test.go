package nmap

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/scanners"
)

// TestExecuteAgainstLocalNmap runs a REAL nmap against loopback only.
// Skipped automatically when nmap is not installed.
func TestExecuteAgainstLocalNmap(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed; skipping integration test")
	}
	m := nmapManifest(t)
	m.Configuration.Timeout = 300
	s, err := New(m)
	require.NoError(t, err)

	res, err := s.Execute(context.Background(), scanners.ScanRequest{
		SessionID:   uuid.New(),
		ExecutionID: uuid.New(),
		Targets:     []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		Config: scanners.ScannerConfig{
			"scan_intensity":    "ping_only",
			"skip_ping":         true,
			"service_detection": false,
		},
		WorkDir: t.TempDir(),
		Timeout: 3 * time.Minute,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.RawOutput, "nmap XML output captured")
	assert.Contains(t, string(res.RawOutput), "<nmaprun")

	found := false
	for _, a := range res.Assets {
		if a.Identity == "127.0.0.1" {
			found = true
		}
	}
	assert.True(t, found, "loopback host observed, got %v", res.Assets)
}

// TestExecuteAgainstLocalNmapTopPorts runs a real service-scan on loopback
// with the Lead-approved flags (-Pn --top-ports 100 -sC equivalent via
// config) and validates the full normalize pipeline end to end.
func TestExecuteAgainstLocalNmapTopPorts(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed; skipping integration test")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		t.Log("nc not available; still running scan but open-port assertions are softer")
	}
	m := nmapManifest(t)
	s, err := New(m)
	require.NoError(t, err)

	res, err := s.Execute(context.Background(), scanners.ScanRequest{
		SessionID:   uuid.New(),
		ExecutionID: uuid.New(),
		Targets:     []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		Config: scanners.ScannerConfig{
			"skip_ping":         true,
			"ports":             "1-100",
			"service_detection": true,
			"scripts":           true,
			"max_parallelism":   10.0,
		},
		WorkDir: t.TempDir(),
		Timeout: 5 * time.Minute,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Assets)

	var host *scanners.AssetObservationData
	for i := range res.Assets {
		if res.Assets[i].Identity == "127.0.0.1" {
			host = &res.Assets[i]
		}
	}
	require.NotNil(t, host)
	for _, p := range host.Ports {
		assert.Contains(t, []string{"open", "closed", "filtered", "unfiltered"}, p.State)
		assert.Equal(t, "tcp", p.Protocol)
	}
	// Every finding on loopback must be evidence-backed with script output.
	for _, f := range res.Findings {
		assert.NotEmpty(t, f.Evidence.Output, "finding %q lacks evidence", f.Title)
		assert.NotEmpty(t, f.Evidence.Script)
	}
}
