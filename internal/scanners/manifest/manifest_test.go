package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validManifest() *Manifest {
	min1, max128 := 1.0, 128.0
	return &Manifest{
		Name:         "nmap",
		DisplayName:  "Nmap",
		Description:  "Network discovery",
		Version:      "auto",
		Executable:   "nmap",
		Adapter:      AdapterCommand,
		Enabled:      true,
		AssetTypes:   []string{"ip", "hostname"},
		Capabilities: []string{"host_discovery", "port_discovery", "os_detection", "vulnerability_detection"},
		Output:       OutputSpec{Format: FormatXML, Parser: "nmap_xml"},
		Configuration: Configuration{
			Timeout: 1800,
			Options: []OptionSpec{
				{ID: "service_detection", Label: "Service Detection", Type: OptionBoolean, Default: true},
				{ID: "os_detection", Label: "OS Detection", Type: OptionBoolean, Default: false},
				{ID: "scripts", Label: "NSE Scripts", Type: OptionMultiselect,
					Options: []string{"default", "safe", "vuln"}},
				{ID: "timing", Label: "Timing", Type: OptionSelect, Default: "normal",
					Options: []string{"slow", "normal", "fast"}},
				{ID: "max_parallelism", Label: "Max Parallelism", Type: OptionNumber, Min: &min1, Max: &max128},
			},
		},
	}
}

func TestManifestValidate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Manifest)
		wantError string // substring
	}{
		{"valid", func(m *Manifest) {}, ""},
		{"missing name", func(m *Manifest) { m.Name = "" }, "name is required"},
		{"bad name chars", func(m *Manifest) { m.Name = "Nmap; rm" }, "must match"},
		{"missing display_name", func(m *Manifest) { m.DisplayName = "" }, "display_name is required"},
		{"bad adapter", func(m *Manifest) { m.Adapter = "shell" }, "must be one of command, native"},
		{"command needs executable", func(m *Manifest) { m.Executable = "" }, "executable is required"},
		{"executable shell metachar", func(m *Manifest) { m.Executable = "nmap; rm -rf /" }, "invalid characters"},
		{"executable backtick", func(m *Manifest) { m.Executable = "`evil`" }, "invalid characters"},
		{"executable pipe", func(m *Manifest) { m.Executable = "nmap|sh" }, "invalid characters"},
		{"executable dollar", func(m *Manifest) { m.Executable = "$IFS" }, "invalid characters"},
		{"executable space", func(m *Manifest) { m.Executable = "n map" }, "invalid characters"},
		{"negative timeout", func(m *Manifest) { m.Configuration.Timeout = -5 }, "timeout must be > 0"},
		{"duplicate option ids", func(m *Manifest) {
			m.Configuration.Options = append(m.Configuration.Options,
				OptionSpec{ID: "timing", Label: "Dup", Type: OptionSelect, Options: []string{"a"}})
		}, "duplicate option id"},
		{"option missing id", func(m *Manifest) {
			m.Configuration.Options = append(m.Configuration.Options,
				OptionSpec{Label: "NoID", Type: OptionBoolean})
		}, "option id is required"},
		{"bad option type", func(m *Manifest) {
			m.Configuration.Options = append(m.Configuration.Options,
				OptionSpec{ID: "x", Label: "X", Type: "regex"})
		}, "not in {boolean,string,number,multiselect,select}"},
		{"multiselect needs options", func(m *Manifest) {
			m.Configuration.Options = append(m.Configuration.Options,
				OptionSpec{ID: "m", Label: "M", Type: OptionMultiselect})
		}, "must declare at least one choice"},
		{"select default not in set", func(m *Manifest) {
			m.Configuration.Options = append(m.Configuration.Options,
				OptionSpec{ID: "s", Label: "S", Type: OptionSelect, Default: "ultra", Options: []string{"slow"}})
		}, "not in options"},
		{"boolean default wrong type", func(m *Manifest) {
			m.Configuration.Options = append(m.Configuration.Options,
				OptionSpec{ID: "b", Label: "B", Type: OptionBoolean, Default: "yes"})
		}, "default must be a boolean"},
		{"min greater max", func(m *Manifest) {
			hi, lo := 1.0, 9.0
			m.Configuration.Options = append(m.Configuration.Options,
				OptionSpec{ID: "n", Label: "N", Type: OptionNumber, Min: &hi, Max: &lo})
		}, "min > max"},
		{"empty asset types", func(m *Manifest) { m.AssetTypes = nil }, "asset_types must not be empty"},
		{"bad asset type", func(m *Manifest) { m.AssetTypes = []string{"mac"} }, "not in {ip,ipv6"},
		{"empty capabilities", func(m *Manifest) { m.Capabilities = nil }, "capabilities must not be empty"},
		{"bad capability", func(m *Manifest) { m.Capabilities = []string{"rootkit"} }, "not an allowed capability"},
		{"bad output format", func(m *Manifest) { m.Output.Format = "yaml" }, "output.format"},
		{"missing parser", func(m *Manifest) { m.Output.Parser = "" }, "output.parser is required"},
		{"bad exit code", func(m *Manifest) { m.Configuration.AcceptableExitCodes = []int{300} }, "out of range"},
		{"unknown placeholder", func(m *Manifest) { m.Arguments = []string{"--out", "{{file}}"} }, "unknown"},
		{"native needs no executable", func(m *Manifest) {
			m.Adapter = AdapterNative
			m.Executable = ""
			m.Output = OutputSpec{Format: FormatNone, Parser: "tcp_connect_probe"}
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mutate(m)
			err := m.Validate()
			if tc.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantError)
		})
	}
}

func TestParseYAML(t *testing.T) {
	doc := `
name: nmap
display_name: Nmap
description: Network discovery and vulnerability assessment
version: auto
executable: nmap
adapter: command
enabled: true
asset_types: [ip, hostname]
capabilities: [host_discovery, port_discovery, service_detection, os_detection, vulnerability_detection]
output: {format: xml, parser: nmap_xml}
configuration:
  timeout: 1800
  options:
    - {id: service_detection, label: Service Detection, type: boolean, default: true}
    - {id: os_detection, label: OS Detection, type: boolean, default: false}
    - {id: scripts, label: NSE Scripts, type: multiselect, options: [default, safe, vuln]}
`
	m, err := Parse([]byte(doc))
	require.NoError(t, err)
	assert.Equal(t, "nmap", m.Name)
	assert.Equal(t, 1800, m.Configuration.Timeout)
	require.Len(t, m.Configuration.Options, 3)
	assert.Equal(t, true, m.Configuration.Options[0].Default)

	_, err = Parse([]byte(strings.Replace(doc, "timeout: 1800", "timeout: 0\n  bogus_key: 1", 1)))
	require.Error(t, err, "unknown YAML fields must be rejected")
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	base := `name: %s
display_name: D
executable: tool
adapter: command
enabled: true
asset_types: [ip]
capabilities: [port_discovery]
output: {format: text, parser: none}
configuration: {timeout: 60}
`
	write("a.yaml", "name: b1\ndisplay_name: D\nadapter: native\nasset_types: [ip]\ncapabilities: [port_discovery]\noutput: {format: none, parser: none}\nconfiguration: {timeout: 60}\n")
	write("b.yml", "name: a1\ndisplay_name: D\nadapter: native\nasset_types: [ip]\ncapabilities: [port_discovery]\noutput: {format: none, parser: none}\nconfiguration: {timeout: 60}\n")
	write("ignore.txt", "not a manifest")

	mfs, err := LoadDir(dir)
	require.NoError(t, err)
	require.Len(t, mfs, 2)
	assert.Equal(t, "a1", mfs[0].Name, "sorted by name")
	assert.Equal(t, "b1", mfs[1].Name)

	// duplicate name in another file must error
	write("c.yaml", "name: a1\ndisplay_name: D\nadapter: native\nasset_types: [ip]\ncapabilities: [port_discovery]\noutput: {format: none, parser: none}\nconfiguration: {timeout: 60}\n")
	_, err = LoadDir(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate scanner name")

	// invalid manifest surfaces its filename
	write("broken.yaml", "name: x\ndisplay_name: D\nadapter: warp-drive\nasset_types: [ip]\ncapabilities: [port_discovery]\noutput: {format: none, parser: none}\n")
	_, err = LoadDir(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken.yaml")
}

func TestBundledConfigsValidate(t *testing.T) {
	// The shipped configs under configs/scanners must load cleanly.
	mfs, err := LoadDir(filepath.Join("..", "..", "..", "configs", "scanners"))
	require.NoError(t, err, "bundled scanner configs must be valid")
	names := map[string]bool{}
	for _, m := range mfs {
		names[m.Name] = true
	}
	assert.True(t, names["nmap"])
	assert.True(t, names["nuclei"])
	assert.True(t, names["nativeprobe"])
}

func TestValidateConfig(t *testing.T) {
	m := validManifest()
	tests := []struct {
		name      string
		config    scanners.ScannerConfig
		wantError string
	}{
		{"empty", scanners.ScannerConfig{}, ""},
		{"valid bool", scanners.ScannerConfig{"os_detection": true}, ""},
		{"valid select", scanners.ScannerConfig{"timing": "fast"}, ""},
		{"select not allowed", scanners.ScannerConfig{"timing": "insane"}, "not in allowed set"},
		{"multiselect valid", scanners.ScannerConfig{"scripts": []any{"safe", "vuln"}}, ""},
		{"multiselect one bad", scanners.ScannerConfig{"scripts": []any{"safe", "exploit"}}, "not in allowed set"},
		{"multiselect string form", scanners.ScannerConfig{"scripts": "safe"}, ""},
		{"bool wrong type", scanners.ScannerConfig{"os_detection": "true"}, "expected boolean"},
		{"number below min", scanners.ScannerConfig{"max_parallelism": 0.5}, "below minimum"},
		{"number above max", scanners.ScannerConfig{"max_parallelism": float64(999)}, "above maximum"},
		{"number json encoding", scanners.ScannerConfig{"max_parallelism": json.Number("20")}, ""},
		{"unknown key", scanners.ScannerConfig{"sudo_me": true}, "unknown configuration option"},
		{"nil value skipped", scanners.ScannerConfig{"os_detection": nil}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfig(m.Configuration.Options, tc.config)
			if tc.wantError == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantError)
			}
		})
	}
}

func TestValidateConfigStringSafety(t *testing.T) {
	min1, max1 := 1.0, 100.0
	opts := []OptionSpec{
		{ID: "ports", Label: "Ports", Type: OptionString},
		{ID: "n", Label: "N", Type: OptionNumber, Min: &min1, Max: &max1},
	}
	injections := []string{
		"; rm -rf /",
		"$(curl evil)",
		"`whoami`",
		"a b",              // space
		"--evil",           // flag injection
		"a\nb",             // newline (also caught as control char)
		"a|cat /etc/passwd", // pipe
		"nmap && id",
		"a>b",
	}
	for _, inj := range injections {
		t.Run("reject "+inj, func(t *testing.T) {
			err := ValidateConfig(opts, scanners.ScannerConfig{"ports": inj})
			require.Error(t, err, "injection attempt %q must be rejected", inj)
		})
	}
	for _, ok := range []string{"22,80,443,8000-8100", "top-1000", "safe,vuln", "a_b-c.d:e/f=g+h"} {
		t.Run("accept "+ok, func(t *testing.T) {
			require.NoError(t, ValidateConfig(opts, scanners.ScannerConfig{"ports": ok}))
		})
	}
}

func TestManifestJSON(t *testing.T) {
	m := validManifest()
	raw, err := m.JSON()
	require.NoError(t, err)
	var back map[string]any
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, "nmap", back["name"])
	assert.Equal(t, AdapterCommand, back["adapter"])
	assert.Equal(t, 1800.0, back["configuration"].(map[string]any)["timeout"])
}

func TestHelperAccessors(t *testing.T) {
	m := validManifest()
	assert.Equal(t, "xml", m.DefaultExtension())
	m.Output.Format = FormatNone
	assert.Equal(t, "out", m.DefaultExtension())
	m.Output.Extension = "jsonl"
	assert.Equal(t, "jsonl", m.DefaultExtension())

	o, ok := m.Option("timing")
	require.True(t, ok)
	assert.Equal(t, OptionSelect, o.Type)
	_, ok = m.Option("nope")
	assert.False(t, ok)

	assert.Equal(t, 1800, m.TimeoutSeconds())
	m.Configuration.Timeout = 0
	assert.Equal(t, 1800, m.TimeoutSeconds(), "zero falls back to default")
}
