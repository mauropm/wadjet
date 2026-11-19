// Package manifest loads and validates scanner manifest files. A manifest is
// a YAML document that declaratively describes an integrated security tool:
// its executable, adapter kind, supported asset types and capabilities,
// user-settable configuration options, and output format.
//
// Manifests are untrusted configuration: everything parsed from a manifest is
// validated against strict allowlists before it may influence anything the
// engine executes or persists.
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Adapter kinds.
const (
	AdapterCommand = "command"
	AdapterNative  = "native"
)

// Option types allowed in manifests.
const (
	OptionBoolean     = "boolean"
	OptionString      = "string"
	OptionNumber      = "number"
	OptionMultiselect = "multiselect"
	OptionSelect      = "select"
)

// Output formats allowed in manifests.
const (
	FormatXML  = "xml"
	FormatJSON = "json"
	FormatText = "text"
	FormatCSV  = "csv"
	FormatNone = "none"
)

// nameRe accepts lowercase slug names (manifest names, option ids).
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// executableRe accepts a bare program name or an absolute/relative-free
// path. Deliberately excludes every shell metacharacter: ; | & $ ` ( ) < >
// ' " \ space, tab, newline, glob characters and braces.
// executableRe validates manifest executable paths (SEC-005). Accepted
// forms: a bare PATH-resolved binary name, or an absolute path. Relative
// paths with directory components are rejected (manifest-directory
// confusion), and the ".." sequence is rejected separately so a manifest
// cannot point at an attacker-supplied binary inside the config tree.
var executableRe = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9._+@-]*|/[A-Za-z0-9][A-Za-z0-9._+@/-]*)$`)

// hostnameLike asset types accepted from manifests. These mirror the
// Target.Type vocabulary in internal/scanners/scanner.go.
var allowedAssetTypes = map[string]bool{
	"ip":       true,
	"ipv6":     true,
	"hostname": true,
	"domain":   true,
	"cidr":     true,
	"url":      true,
}

// allowedCapabilities mirrors the Capability constants in
// internal/scanners/scanner.go. Kept in sync manually; scanner.go is a
// frozen shared contract.
var allowedCapabilities = map[string]bool{
	"host_discovery":          true,
	"port_discovery":          true,
	"service_detection":       true,
	"version_detection":       true,
	"os_detection":            true,
	"vulnerability_detection": true,
	"web_discovery":           true,
	"tls_assessment":          true,
}

var allowedOptionTypes = map[string]bool{
	OptionBoolean:     true,
	OptionString:      true,
	OptionNumber:      true,
	OptionMultiselect: true,
	OptionSelect:      true,
}

var allowedFormats = map[string]bool{
	FormatXML:  true,
	FormatJSON: true,
	FormatText: true,
	FormatCSV:  true,
	FormatNone: true,
}

// OutputSpec describes the scanner's native output.
type OutputSpec struct {
	Format string `yaml:"format" json:"format"`
	Parser string `yaml:"parser" json:"parser"`
	// Extension is the file extension used when persisting raw output.
	// Defaults are derived from Format when empty.
	Extension string `yaml:"extension" json:"extension"`
}

// OptionSpec declares one user-settable scanner option.
type OptionSpec struct {
	ID      string   `yaml:"id" json:"id"`
	Label   string   `yaml:"label" json:"label"`
	Type    string   `yaml:"type" json:"type"`
	Default any      `yaml:"default" json:"default"`
	Options []string `yaml:"options" json:"options"`
	Min     *float64 `yaml:"min" json:"min"`
	Max     *float64 `yaml:"max" json:"max"`
}

// Configuration holds scanner runtime configuration declared by the manifest.
type Configuration struct {
	// Timeout is the default per-execution timeout in seconds. Must be > 0.
	Timeout int `yaml:"timeout" json:"timeout"`
	// AcceptableExitCodes lists additional process exit codes that mean
	// "success" for this scanner (exit 0 is always acceptable).
	AcceptableExitCodes []int `yaml:"acceptable_exit_codes" json:"acceptable_exit_codes"`
	// EnvAllowlist lists environment variable names passed through to the
	// scanner process. The process otherwise receives a minimal environment.
	EnvAllowlist []string     `yaml:"env_allowlist" json:"env_allowlist"`
	Options      []OptionSpec `yaml:"options" json:"options"`
}

// Manifest is the parsed, validated description of one scanner integration.
type Manifest struct {
	Name         string   `yaml:"name" json:"name"`
	DisplayName  string   `yaml:"display_name" json:"display_name"`
	Description  string   `yaml:"description" json:"description"`
	Version      string   `yaml:"version" json:"version"`
	Executable   string   `yaml:"executable" json:"executable"`
	Adapter      string   `yaml:"adapter" json:"adapter"`
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AssetTypes   []string `yaml:"asset_types" json:"asset_types"`
	Capabilities []string `yaml:"capabilities" json:"capabilities"`

	Output        OutputSpec    `yaml:"output" json:"output"`
	Configuration Configuration `yaml:"configuration" json:"configuration"`

	// Arguments is the fixed, operator-authored argument template used by
	// the generic command adapter. Placeholders {{target}} and {{workdir}}
	// are substituted as whole argv elements; user configuration values are
	// never interpolated into arguments.
	Arguments []string `yaml:"arguments" json:"arguments"`

	// Documentation is an optional URL or notes shown in the UI.
	Documentation string `yaml:"documentation" json:"documentation"`

	// SourceFile records where the manifest was loaded from (not serialized).
	SourceFile string `yaml:"-" json:"-"`
}

// DefaultExtension returns the file extension for raw output files.
func (m *Manifest) DefaultExtension() string {
	if m.Output.Extension != "" {
		return m.Output.Extension
	}
	switch m.Output.Format {
	case FormatXML:
		return "xml"
	case FormatJSON:
		return "json"
	case FormatCSV:
		return "csv"
	case FormatText:
		return "txt"
	default:
		return "out"
	}
}

// Option returns the option declaration with the given id, if any.
func (m *Manifest) Option(id string) (*OptionSpec, bool) {
	for i := range m.Configuration.Options {
		if m.Configuration.Options[i].ID == id {
			return &m.Configuration.Options[i], true
		}
	}
	return nil, false
}

// TimeoutSeconds returns the manifest timeout, defaulting to 1800s.
func (m *Manifest) TimeoutSeconds() int {
	if m.Configuration.Timeout > 0 {
		return m.Configuration.Timeout
	}
	return 1800
}

// Validate enforces every structural rule required before a manifest may be
// persisted or executed. It returns all problems at once.
func (m *Manifest) Validate() error {
	var errs []string
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if m.Name == "" {
		add("name is required")
	} else if !nameRe.MatchString(m.Name) {
		add("name %q must match %s", m.Name, nameRe.String())
	}
	if strings.TrimSpace(m.DisplayName) == "" {
		add("display_name is required")
	}

	switch m.Adapter {
	case AdapterCommand:
		if m.Executable == "" {
			add("executable is required for command adapters")
		}
	case AdapterNative:
		// Native scanners run in-process; no executable is required.
	default:
		add("adapter %q must be one of command, native", m.Adapter)
	}

	if m.Executable != "" && (strings.Contains(m.Executable, "..") || !executableRe.MatchString(m.Executable)) {
		add("executable %q contains invalid characters (shell metacharacters, "+
			"spaces and glob characters are rejected)", m.Executable)
	}

	if m.Configuration.Timeout < 0 {
		add("configuration.timeout must be > 0")
	}

	seen := map[string]bool{}
	for _, o := range m.Configuration.Options {
		if o.ID == "" {
			add("option id is required")
			continue
		}
		if !nameRe.MatchString(o.ID) {
			add("option id %q must match %s", o.ID, nameRe.String())
		}
		if seen[o.ID] {
			add("duplicate option id %q", o.ID)
		}
		seen[o.ID] = true
		if strings.TrimSpace(o.Label) == "" {
			add("option %q: label is required", o.ID)
		}
		if !allowedOptionTypes[o.Type] {
			add("option %q: type %q not in {boolean,string,number,multiselect,select}", o.ID, o.Type)
			continue
		}
		switch o.Type {
		case OptionMultiselect, OptionSelect:
			if len(o.Options) == 0 {
				add("option %q: %s options must declare at least one choice", o.ID, o.Type)
			}
			if err := checkDefaultInSet(o); err != nil {
				add("option %q: %v", o.ID, err)
			}
		case OptionNumber:
			if o.Min != nil && o.Max != nil && *o.Min > *o.Max {
				add("option %q: min > max", o.ID)
			}
		}
		if o.Type == OptionBoolean {
			if _, ok := o.Default.(bool); !ok && o.Default != nil {
				add("option %q: default must be a boolean", o.ID)
			}
		}
	}

	if len(m.AssetTypes) == 0 {
		add("asset_types must not be empty")
	}
	for _, a := range m.AssetTypes {
		if !allowedAssetTypes[a] {
			add("asset_types: %q not in {ip,ipv6,hostname,domain,cidr,url}", a)
		}
	}
	if len(m.Capabilities) == 0 {
		add("capabilities must not be empty")
	}
	for _, c := range m.Capabilities {
		if !allowedCapabilities[c] {
			add("capabilities: %q not an allowed capability", c)
		}
	}

	if !allowedFormats[m.Output.Format] {
		add("output.format %q not in {xml,json,text,csv,none}", m.Output.Format)
	}
	if m.Output.Format != FormatNone && m.Output.Parser == "" {
		add("output.parser is required when output.format is not none")
	}

	for _, code := range m.Configuration.AcceptableExitCodes {
		if code <= 0 || code > 255 {
			add("acceptable_exit_codes: %d out of range 1-255", code)
		}
	}

	for _, a := range m.Arguments {
		for _, ph := range unknownPlaceholders(a) {
			add("arguments: placeholder %q unknown (allowed: {{target}}, {{workdir}})", ph)
		}
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("manifest %q invalid: %s", m.Name, strings.Join(errs, "; "))
	}
	return nil
}

func checkDefaultInSet(o OptionSpec) error {
	switch d := o.Default.(type) {
	case nil:
		return nil
	case string:
		if !containsString(o.Options, d) {
			return fmt.Errorf("default %q not in options", d)
		}
	case []any:
		for _, v := range d {
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("default list element %v is not a string", v)
			}
			if !containsString(o.Options, s) {
				return fmt.Errorf("default %q not in options", s)
			}
		}
	default:
		return fmt.Errorf("default %v is not a string or list of strings", o.Default)
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

var placeholderRe = regexp.MustCompile(`\{\{\s*([^}]*?)\s*\}\}`)

// knownPlaceholders are the only template placeholders accepted in
// manifest argument templates.
var knownPlaceholders = map[string]bool{"target": true, "workdir": true}

func unknownPlaceholders(arg string) []string {
	var out []string
	for _, g := range placeholderRe.FindAllStringSubmatch(arg, -1) {
		if !knownPlaceholders[g[1]] {
			out = append(out, g[1])
		}
	}
	return out
}

// JSON returns the manifest serialized for the scanners.manifest JSONB
// column. It round-trips through the YAML field names.
func (m *Manifest) JSON() (json.RawMessage, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest %s: %w", m.Name, err)
	}
	return b, nil
}

// Parse decodes a single manifest document from YAML bytes.
func Parse(data []byte) (*Manifest, error) {
	m := &Manifest{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// LoadFile reads, parses and validates a single manifest file.
func LoadFile(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	m, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", filepath.Base(path), err)
	}
	m.SourceFile = path
	return m, nil
}

// LoadDir loads every *.yaml / *.yml manifest in dir, validates them, and
// returns them sorted by name. Duplicate scanner names are an error.
func LoadDir(dir string) ([]*Manifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read manifest dir %s: %w", dir, err)
	}
	var out []*Manifest
	seen := map[string]string{}
	var errs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		m, err := LoadFile(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if prev, dup := seen[m.Name]; dup {
			errs = append(errs, fmt.Sprintf("manifest %s: duplicate scanner name %q (also in %s)", path, m.Name, prev))
			continue
		}
		seen[m.Name] = path
		out = append(out, m)
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errors.New("manifest load errors: " + strings.Join(errs, "; "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
