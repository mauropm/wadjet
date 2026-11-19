package command

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

// timeoutAfter bounds tests that must not hang.
func timeoutAfter() <-chan time.Time { return time.After(15 * time.Second) }

func testManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m := &manifest.Manifest{
		Name:        "echotool",
		DisplayName: "Echo Tool",
		Description: "test",
		Executable:  "/bin/echo",
		Adapter:     manifest.AdapterCommand,
		Enabled:     true,
		AssetTypes:  []string{"ip", "hostname"},
		Capabilities: []string{"port_discovery"},
		Output:      manifest.OutputSpec{Format: manifest.FormatText, Parser: "none"},
		Configuration: manifest.Configuration{Timeout: 30},
		Arguments:   []string{"-n", "scan", "{{workdir}}/out.txt", "{{target}}"},
	}
	require.NoError(t, m.Validate())
	return m
}

func TestBuildArgs(t *testing.T) {
	m := testManifest(t)
	req := scanners.ScanRequest{
		Targets: []scanners.Target{
			{Raw: "10.0.0.1", Type: "ip"},
			{Raw: "example.com", Type: "hostname"},
		},
		WorkDir: "/tmp/work",
	}
	args, err := BuildArgs(m, req)
	require.NoError(t, err)
	assert.Equal(t, []string{"-n", "scan", "/tmp/work/out.txt", "10.0.0.1", "example.com"}, args,
		"placeholders expand as discrete argv elements")
}

func TestBuildArgsRejections(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		targets []string
	}{
		{"unknown placeholder", []string{"{{file}}"}, []string{"10.0.0.1"}},
		{"nested bad placeholder", []string{"--out={{host}}"}, []string{"10.0.0.1"}},
		{"shell metachar in literal arg", []string{"--flag; rm -rf /"}, []string{"10.0.0.1"}},
		{"backtick in literal arg", []string{"--x=`id`"}, []string{"10.0.0.1"}},
		{"injection in target", []string{"{{target}}"}, []string{"10.0.0.1; rm -rf /"}},
		{"space in target", []string{"{{target}}"}, []string{"10.0.0.1 && id"}},
		{"flag injection as target", []string{"{{target}}"}, []string{"--evil"}},
		{"empty targets", []string{"{{target}}"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := testManifest(t)
			m.Arguments = tc.args
			var targets []scanners.Target
			for _, raw := range tc.targets {
				targets = append(targets, scanners.Target{Raw: raw, Type: "ip"})
			}
			_, err := BuildArgs(m, scanners.ScanRequest{Targets: targets, WorkDir: "/tmp/w"})
			require.Error(t, err)
		})
	}
}

func TestExecuteEcho(t *testing.T) {
	m := testManifest(t)
	m.Arguments = []string{"hello", "{{target}}"}
	adapter, err := New(m, nil)
	require.NoError(t, err)

	work := t.TempDir()
	res, err := adapter.Execute(context.Background(), scanners.ScanRequest{
		SessionID:   uuid.New(),
		ExecutionID: uuid.New(),
		Targets:     []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		Config:      scanners.ScannerConfig{},
		WorkDir:     work,
		Timeout:     10 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, "hello 127.0.0.1", strings.TrimSpace(string(res.RawOutput)))
	_, statErr := os.Stat(filepath.Join(work, "stdout.txt"))
	assert.NoError(t, statErr, "stdout captured to workdir file")
}

func TestExecuteMissingExecutable(t *testing.T) {
	m := testManifest(t)
	m.Executable = "/nonexistent/wadjet-test-binary"
	adapter, err := New(m, nil)
	require.NoError(t, err)
	_, err = adapter.Execute(context.Background(), scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		WorkDir: t.TempDir(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wadjet-test-binary")
}

func TestExecuteAcceptableExitCode(t *testing.T) {
	m := testManifest(t)
	m.Executable = "/usr/bin/false"
	m.Arguments = nil
	m.Configuration.AcceptableExitCodes = []int{1}
	adapter, err := New(m, nil)
	require.NoError(t, err)
	res, err := adapter.Execute(context.Background(), scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		WorkDir: t.TempDir(),
	})
	require.NoError(t, err, "declared acceptable exit code must not fail the execution")
	assert.NotNil(t, res)

	m.Configuration.AcceptableExitCodes = nil
	adapter, err = New(m, nil)
	require.NoError(t, err)
	_, err = adapter.Execute(context.Background(), scanners.ScanRequest{
		Targets: []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
		WorkDir: t.TempDir(),
	})
	require.Error(t, err, "unexpected exit code must fail")
}

func TestExecuteCancellation(t *testing.T) {
	m := testManifest(t)
	m.Executable = "/bin/sleep"
	m.Arguments = []string{"30"}
	adapter, err := New(m, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := adapter.Execute(ctx, scanners.ScanRequest{
			Targets: []scanners.Target{{Raw: "127.0.0.1", Type: "ip"}},
			WorkDir: t.TempDir(),
		})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cancelled")
	case <-timeoutAfter():
		t.Fatal("execution did not honour cancellation")
	}
}

func TestValidateTarget(t *testing.T) {
	m := testManifest(t)
	adapter, err := New(m, nil)
	require.NoError(t, err)
	require.NoError(t, adapter.ValidateTarget(scanners.Target{Raw: "1.2.3.4", Type: "ip"}))
	require.Error(t, adapter.ValidateTarget(scanners.Target{Raw: "http://x", Type: "url"}))
}

func TestValidateConfigDelegates(t *testing.T) {
	m := testManifest(t)
	m.Configuration.Options = []manifest.OptionSpec{
		{ID: "mode", Label: "Mode", Type: manifest.OptionSelect, Options: []string{"fast"}},
	}
	adapter, err := New(m, nil)
	require.NoError(t, err)
	require.NoError(t, adapter.ValidateConfig(scanners.ScannerConfig{"mode": "fast"}))
	require.Error(t, adapter.ValidateConfig(scanners.ScannerConfig{"mode": "insane"}))
	require.Error(t, adapter.ValidateConfig(scanners.ScannerConfig{"nope": 1}))
}

func TestBuildEnvAllowlist(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("SECRET_TOKEN", "do-not-leak")
	t.Setenv("WADJET_TEST", "passthrough")
	env := buildEnv([]string{"WADJET_TEST"})
	joined := strings.Join(env, "\n")
	assert.Contains(t, joined, "PATH=/usr/bin")
	assert.Contains(t, joined, "WADJET_TEST=passthrough")
	assert.NotContains(t, joined, "SECRET_TOKEN", "non-allowlisted variables must be withheld")
}

func TestTruncWriter(t *testing.T) {
	w := &truncWriter{limit: 10}
	n, err := w.Write([]byte("0123456789ABCDEF"))
	require.NoError(t, err)
	assert.Equal(t, 16, n, "io.Writer contract: report full consumption")
	s := w.String()
	assert.Equal(t, "0123456789", s[:10])
	assert.Contains(t, s, "truncated")
}

func TestNewRejectsMismatchedManifest(t *testing.T) {
	m := testManifest(t)
	m.Adapter = manifest.AdapterNative
	_, err := New(m, nil)
	require.Error(t, err)

	m = testManifest(t)
	m.Executable = ""
	_, err = New(m, nil)
	require.Error(t, err)
}
