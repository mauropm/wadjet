// Package nmap integrates Nmap: allowlist-driven argument construction, an
// XML output parser, and a curated classifier that turns NSE script output
// into normalized findings.
//
// Security model:
//
//   - Flags are assembled exclusively from fixed, code-owned fragments. A
//     user-supplied value reaches argv only after passing a strict
//     allowlist/regex check for its specific option.
//   - Values that fail validation abort the execution with an error; they
//     are never sanitized-and-passed.
//   - Nmap XML output is untrusted input and is parsed defensively.
package nmap

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

// OutputFileName is where raw nmap XML lands when not using stdout mode.
const OutputFileName = "nmap-run.xml"

// scanIntensity values accepted for the "scan_intensity" option.
const (
	IntensityPingOnly = "ping_only"
	IntensityTop1000  = "top1000"
	IntensityCommon   = "common"
	IntensityFull     = "full"
)

// ScanIntensities is the allowed set for manifest option declarations.
var ScanIntensities = []string{IntensityPingOnly, IntensityTop1000, IntensityCommon, IntensityFull}

// TimingTemplates maps the "timing" option to -T levels.
var TimingTemplates = map[string]string{
	"slow":   "-T2",
	"normal": "-T3",
	"fast":   "-T4",
}

// ScriptCategories is the allowlist of NSE categories usable in the
// "script_categories" option. Dangerous categories (intrusive, dos, exploit,
// fuzzer, malware, all) are intentionally absent.
var ScriptCategories = []string{
	// SECURITY: brute (password guessing), broadcast and external (touch
	// third-party infrastructure beyond the target) are deliberately absent.
	"default", "safe", "vuln", "discovery", "auth", "version",
}

// KnownScripts is the allowlist of individually selectable NSE script ids
// for the "custom_scripts" option. Only scripts that are safe to run in a
// default assessment are listed.
var KnownScripts = []string{
	"banner", "clock-skew", "dns-zone-transfer", "ftp-anon", "ftp-syst",
	"http-headers", "http-methods", "http-robots-txt", "http-server-header",
	"http-sql-injection", "http-stored-xss", "http-title", "http-traceroute",
	"http-userdir-enum", "http-vuln-cve2017-5638", "http-vuln-cve2021-41773",
	"https-redirect", "iscsi-targets", "nbstat", "ntp-info", "p0f-fingerprint",
	"smb-os-discovery", "smb-protocols", "smb-security-mode", "snmp-info",
	"snmp-sysdescr", "ssh-hostkey", "ssh-kex-weak-algos", "ssh2-enum-algos",
	"ssl-date", "ssl-enum-ciphers", "ssl-known-key", "sslv2", "sslv2-drown",
	"telnet-echo", "tls-nextprotoneg", "tls-info", "vhosts", "xmpp-info",
}

var (
	// portsRe accepts comma-separated ports and ranges: 22,80,443,8000-8100
	portsRe = regexp.MustCompile(`^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*$`)
	// scriptTokenRe accepts a single NSE script name or category token.
	scriptTokenRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// hostTimeoutRe accepts nmap --host-timeout values: 300s, 5m, 2h, 300.
	hostTimeoutRe = regexp.MustCompile(`^[0-9]+(?:ms|s|m|h)?$`)
)

// maxCustomPorts caps the number of ports in an explicit custom range so a
// misconfiguration cannot silently schedule a 65535-port sweep.
const maxCustomPorts = 65535

// BuildArgs renders the full nmap argv for a request. Every fragment is
// either fixed (owned by this file) or a config value that has passed strict
// validation. Targets are appended last as discrete elements.
//
// XML output is emitted to stdout via -oX -; the command adapter captures
// stdout to the execution's output file.
func BuildArgs(m *manifest.Manifest, req scanners.ScanRequest) ([]string, error) {
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("nmap: no targets supplied")
	}
	cfg := req.Config

	args := []string{"-oX", "-", "--stylesheet=/dev/null"}

	// Port selection: explicit ports win, otherwise intensity.
	if portsRaw, ok := cfg["ports"]; ok && portsRaw != nil {
		ports, ok := portsRaw.(string)
		if !ok {
			return nil, fmt.Errorf("nmap: ports must be a string")
		}
		if err := ValidatePortRange(ports); err != nil {
			return nil, err
		}
		args = append(args, "-p", ports)
	} else {
		intensity := manifest.StringConfig(cfg, "scan_intensity", IntensityTop1000)
		switch intensity {
		case IntensityPingOnly:
			args = append(args, "-sn")
		case IntensityTop1000:
			args = append(args, "--top-ports", "1000")
		case IntensityCommon:
			args = append(args, "--top-ports", "100")
		case IntensityFull:
			args = append(args, "-p-")
		default:
			return nil, fmt.Errorf("nmap: unknown scan_intensity %q", intensity)
		}
	}

	if manifest.BoolConfig(cfg, "service_detection", false) {
		args = append(args, "-sV")
	}

	if manifest.BoolConfig(cfg, "os_detection", false) {
		if rootCheck() {
			args = append(args, "-O")
		} else {
			slog.Info("nmap: OS detection requested but process is not root; degrading gracefully",
				"detail", "-O requires elevated privileges and was omitted")
		}
	}

	// Script selection. service_detection-style "-sC" via scripts bool,
	// category list and individually allowlisted scripts.
	if manifest.BoolConfig(cfg, "scripts", false) {
		args = append(args, "-sC")
	}
	if cats, ok := cfg["script_categories"]; ok && cats != nil {
		list, err := validateScriptList(cats, ScriptCategories, "script_categories")
		if err != nil {
			return nil, err
		}
		if len(list) > 0 {
			args = append(args, "--script", strings.Join(list, ","))
		}
	}
	if custom, ok := cfg["custom_scripts"]; ok && custom != nil {
		list, err := validateScriptList(custom, KnownScripts, "custom_scripts")
		if err != nil {
			return nil, err
		}
		for _, s := range list {
			// One discrete element per script keeps argv inspection trivial.
			args = append(args, "--script="+s)
		}
	}

	timing := manifest.StringConfig(cfg, "timing", "normal")
	tpl, ok := TimingTemplates[timing]
	if !ok {
		return nil, fmt.Errorf("nmap: unknown timing template %q", timing)
	}
	args = append(args, tpl)

	if ht, ok := cfg["host_timeout"]; ok && ht != nil {
		s, ok := ht.(string)
		if !ok || !hostTimeoutRe.MatchString(s) {
			return nil, fmt.Errorf("nmap: invalid host_timeout %v (want e.g. 300s, 5m)", ht)
		}
		args = append(args, "--host-timeout", s)
	}

	if mp, ok := cfg["max_parallelism"]; ok && mp != nil {
		f := manifest.FloatConfig(cfg, "max_parallelism", 0)
		if f < 1 || f > 128 || f != float64(int(f)) {
			return nil, fmt.Errorf("nmap: max_parallelism must be an integer 1-128")
		}
		args = append(args, "--max-parallelism", strconv.Itoa(int(f)))
	}

	if manifest.BoolConfig(cfg, "reason", true) {
		args = append(args, "--reason")
	}
	if !manifest.BoolConfig(cfg, "reverse_dns", true) {
		args = append(args, "-n")
	}
	if manifest.BoolConfig(cfg, "skip_ping", false) {
		args = append(args, "-Pn")
	}

	for _, t := range req.Targets {
		if err := ValidateTargetSpec(t.Raw); err != nil {
			return nil, err
		}
		args = append(args, t.Raw)
	}
	return args, nil
}

// ValidatePortRange validates an explicit port list "80,443,8000-8100".
func ValidatePortRange(ports string) error {
	if ports == "" || len(ports) > 4096 {
		return fmt.Errorf("nmap: ports list empty or too long")
	}
	if !portsRe.MatchString(ports) {
		return fmt.Errorf("nmap: ports %q rejected by validation", ports)
	}
	count := 0
	for _, part := range strings.Split(ports, ",") {
		loS, hiS, _ := strings.Cut(part, "-")
		lo, err := strconv.Atoi(loS)
		if err != nil || lo < 1 || lo > 65535 {
			return fmt.Errorf("nmap: port %q out of range 1-65535", part)
		}
		hi := lo
		if hiS != "" {
			hi, err = strconv.Atoi(hiS)
			if err != nil || hi < 1 || hi > 65535 {
				return fmt.Errorf("nmap: port %q out of range 1-65535", part)
			}
		}
		if hi < lo {
			return fmt.Errorf("nmap: inverted range %q", part)
		}
		count += hi - lo + 1
		if count > maxCustomPorts {
			return fmt.Errorf("nmap: ports expand to more than %d ports", maxCustomPorts)
		}
	}
	return nil
}

// validateScriptList normalizes a multiselect value and requires every token
// to appear in the given allowlist (categories or known scripts).
func validateScriptList(raw any, allowed []string, optName string) ([]string, error) {
	list, ok := manifest.StringList(raw)
	if !ok {
		return nil, fmt.Errorf("nmap: %s must be a string or list of strings", optName)
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = true
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		for _, tok := range strings.Split(item, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if !scriptTokenRe.MatchString(tok) {
				return nil, fmt.Errorf("nmap: %s token %q rejected by validation", optName, tok)
			}
			if !allowedSet[tok] {
				return nil, fmt.Errorf("nmap: %s %q not in the allowed set", optName, tok)
			}
			out = append(out, tok)
		}
	}
	return out, nil
}

var targetSpecRe = regexp.MustCompile(`^[A-Za-z0-9._:/\-]+$`)

// ValidateTargetSpec is the final gate for target strings entering argv:
// hostnames, IPs, IPv6, CIDRs and simple hostname:port forms — nothing else.
func ValidateTargetSpec(raw string) error {
	if raw == "" || len(raw) > 253 {
		return fmt.Errorf("nmap: invalid target %q", raw)
	}
	if strings.HasPrefix(raw, "-") {
		return fmt.Errorf("nmap: target %q must not start with a dash", raw)
	}
	if !targetSpecRe.MatchString(raw) {
		return fmt.Errorf("nmap: target %q contains invalid characters", raw)
	}
	return nil
}

func isRoot() bool { return os.Geteuid() == 0 }

// rootCheck is overridable in tests.
var rootCheck = isRoot
