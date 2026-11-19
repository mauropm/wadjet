// Package command implements the generic external-command scanner adapter.
//
// Security model (binding):
//
//   - The process is started exclusively via exec.CommandContext with an
//     explicit []string argv. No shell is ever involved and command strings
//     are never constructed.
//   - The executable path comes only from a validated manifest, never from
//     user or request input.
//   - Arguments come only from the manifest's fixed `arguments` template.
//     Placeholders {{target}} and {{workdir}} are substituted as whole,
//     separate argv elements; user-controlled configuration values are never
//     interpolated into the argument list by this generic adapter.
//   - The child process receives a minimal environment plus the manifest's
//     explicit environment allowlist.
//   - Scanner output is untrusted data: it is written to a file and parsed
//     defensively.
package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

// maxStderrBytes caps how much stderr is retained for the execution log.
// maxStdoutBytes caps raw stdout capture on disk AND in memory (SEC-007):
// the parser and raw-output persistence hold this buffer a few times, so
// 64 MiB × concurrency keeps worst-case scanner memory bounded.
const (
	maxStderrBytes = 16 << 10 // 16 KiB
	maxStdoutBytes = 64 << 20 // 64 MiB
)

// OutputParser converts a scanner's raw stdout bytes into normalized
// observations and findings. Registry supplies one per manifest output
// parser key; a nil parser leaves the result without structured data
// (raw output is still persisted by the orchestrator).
type OutputParser interface {
	Parse(raw []byte) (*scanners.ScanResult, error)
}

// ParserFunc adapts a plain function to OutputParser.
type ParserFunc func(raw []byte) (*scanners.ScanResult, error)

// Parse implements OutputParser.
func (f ParserFunc) Parse(raw []byte) (*scanners.ScanResult, error) { return f(raw) }

// Adapter executes an external security tool declared by a manifest.
type Adapter struct {
	manifest *manifest.Manifest
	parser   OutputParser
	version  string
	// argBuild, when set, fully replaces the manifest argument template.
	// Structured adapters (nmap) supply an allowlist-driven builder here.
	// The returned argv is still subject to the same execution guarantees:
	// exec.CommandContext only, no shell, separate elements.
	argBuild func(req scanners.ScanRequest) ([]string, error)
}

// New builds a command adapter for the given manifest. The manifest must
// have been validated (see manifest.LoadDir). parser may be nil for tools
// whose output is only archived raw.
func New(m *manifest.Manifest, parser OutputParser) (*Adapter, error) {
	return NewWithArgBuilder(m, parser, nil)
}

// NewWithArgBuilder builds a command adapter whose argv is produced by
// build instead of the manifest argument template. build must only return
// fixed, allowlist-derived argv fragments; it receives the same
// exec.CommandContext execution guarantees. build may be nil, in which case
// the manifest `arguments` template is used.
func NewWithArgBuilder(m *manifest.Manifest, parser OutputParser,
	build func(req scanners.ScanRequest) ([]string, error)) (*Adapter, error) {
	if m == nil {
		return nil, errors.New("command adapter: nil manifest")
	}
	if m.Adapter != manifest.AdapterCommand {
		return nil, fmt.Errorf("command adapter: manifest %s uses adapter %q", m.Name, m.Adapter)
	}
	if m.Executable == "" {
		return nil, fmt.Errorf("command adapter: manifest %s has no executable", m.Name)
	}
	return &Adapter{manifest: m, parser: parser, version: m.Version, argBuild: build}, nil
}

// SetVersion records the tool version discovered by the registry.
func (a *Adapter) SetVersion(v string) { a.version = v }

// Name returns the manifest scanner name.
func (a *Adapter) Name() string { return a.manifest.Name }

// Version returns the discovered or declared version.
func (a *Adapter) Version() string { return a.version }

// Description returns the manifest description.
func (a *Adapter) Description() string { return a.manifest.Description }

// Manifest exposes the validated manifest (used by the registry).
func (a *Adapter) Manifest() *manifest.Manifest { return a.manifest }

// Capabilities converts the manifest capability list to contract types.
func (a *Adapter) Capabilities() []scanners.Capability {
	out := make([]scanners.Capability, 0, len(a.manifest.Capabilities))
	for _, c := range a.manifest.Capabilities {
		out = append(out, scanners.Capability(c))
	}
	return out
}

// ValidateConfig rejects configuration outside the manifest declaration.
func (a *Adapter) ValidateConfig(config scanners.ScannerConfig) error {
	return manifest.ValidateConfig(a.manifest.Configuration.Options, config)
}

// ValidateTarget rejects target kinds the manifest does not declare.
func (a *Adapter) ValidateTarget(target scanners.Target) error {
	for _, t := range a.manifest.AssetTypes {
		if t == target.Type {
			return nil
		}
	}
	return fmt.Errorf("scanner %s does not support target type %q", a.Name(), target.Type)
}

// BuildArgs renders the manifest argument template against the request. It
// is exported for testing. Substitution is per-element: a placeholder inside
// an element is replaced by the complete value as its own argv entry, so
// values are never word-split and never re-interpreted.
func BuildArgs(m *manifest.Manifest, req scanners.ScanRequest) ([]string, error) {
	var args []string
	for _, tpl := range m.Arguments {
		if tpl == "{{target}}" || tpl == "{{workdir}}" {
			// Whole-element placeholders expand to separate argv elements.
			switch tpl {
			case "{{target}}":
				if len(req.Targets) == 0 {
					return nil, errors.New("command adapter: no targets supplied")
				}
				for _, t := range req.Targets {
					if err := validateTargetArg(t.Raw); err != nil {
						return nil, err
					}
					args = append(args, t.Raw)
				}
			case "{{workdir}}":
				args = append(args, req.WorkDir)
			}
			continue
		}
		// Embedded placeholders: only {{workdir}} may appear embedded
		// (operator-authored path template).
		if strings.Contains(tpl, "{{") {
			expanded := strings.ReplaceAll(tpl, "{{workdir}}", req.WorkDir)
			if strings.Contains(expanded, "{{") || strings.Contains(expanded, "}}") {
				return nil, fmt.Errorf("command adapter: invalid placeholder in argument %q", tpl)
			}
			if err := validateArgLiteral(expanded); err != nil {
				return nil, fmt.Errorf("command adapter: argument %q: %w", tpl, err)
			}
			args = append(args, expanded)
			continue
		}
		if err := validateArgLiteral(tpl); err != nil {
			return nil, fmt.Errorf("command adapter: argument %q: %w", tpl, err)
		}
		args = append(args, tpl)
	}
	return args, nil
}

var targetArgRe = regexp.MustCompile(`^[A-Za-z0-9._:/\-\[\]%]+$`)

// validateTargetArg guards target strings reaching argv. Targets have
// already passed orchestrator normalization; this is defense in depth
// against shell/control characters.
func validateTargetArg(raw string) error {
	if raw == "" || len(raw) > 253 {
		return fmt.Errorf("invalid target %q", raw)
	}
	if strings.HasPrefix(raw, "-") {
		return fmt.Errorf("target %q must not start with a dash", raw)
	}
	if !targetArgRe.MatchString(raw) {
		return fmt.Errorf("target %q contains invalid characters", raw)
	}
	return nil
}

var argLiteralRe = regexp.MustCompile(`^[A-Za-z0-9._:/@+=,\-]*$`)

// validateArgLiteral ensures operator-authored manifest arguments contain
// only inert characters (flags like --top-ports, paths, numbers).
func validateArgLiteral(s string) error {
	if !argLiteralRe.MatchString(s) {
		return fmt.Errorf("argument %q contains invalid characters", s)
	}
	return nil
}

// Execute runs the tool to completion or ctx cancellation.
func (a *Adapter) Execute(ctx context.Context, req scanners.ScanRequest) (*scanners.ScanResult, error) {
	if err := a.ValidateConfig(req.Config); err != nil {
		return nil, fmt.Errorf("scanner %s: %w", a.Name(), err)
	}
	for _, t := range req.Targets {
		if err := a.ValidateTarget(t); err != nil {
			return nil, fmt.Errorf("scanner %s: %w", a.Name(), err)
		}
	}
	var args []string
	var err error
	if a.argBuild != nil {
		args, err = a.argBuild(req)
		if err != nil {
			return nil, fmt.Errorf("scanner %s: %w", a.Name(), err)
		}
	} else {
		args, err = BuildArgs(a.manifest, req)
		if err != nil {
			return nil, fmt.Errorf("scanner %s: %w", a.Name(), err)
		}
	}

	runCtx := ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	outPath := filepath.Join(req.WorkDir, "stdout."+a.manifest.DefaultExtension())
	outFile, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("scanner %s: create output file: %w", a.Name(), err)
	}
	defer outFile.Close()
	// SECURITY (SEC-011): a rogue or runaway scanner must not fill the disk.
	// Output beyond maxStdoutBytes is discarded (and flagged below).
	stdout := &cappedWriter{w: outFile, remaining: maxStdoutBytes}

	stderr := &truncWriter{limit: maxStderrBytes}
	cmd := exec.CommandContext(runCtx, a.manifest.Executable, args...)
	cmd.Dir = req.WorkDir
	cmd.Env = buildEnv(a.manifest.Configuration.EnvAllowlist)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second

	slog.Debug("command adapter: executing",
		"scanner", a.Name(), "executable", a.manifest.Executable, "args", args)

	runErr := cmd.Run()
	if err := outFile.Sync(); err != nil {
		slog.Warn("command adapter: sync output file", "err", err)
	}

	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("scanner %s: timed out after %s", a.Name(), req.Timeout)
		}
		if errors.Is(runCtx.Err(), context.Canceled) {
			return nil, fmt.Errorf("scanner %s: cancelled", a.Name())
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && a.exitAcceptable(exitErr.ExitCode()) {
			// Scanner-signalled non-error completion (e.g. nmap exit 2 for
			// some host errors) — continue with whatever output was produced.
			slog.Info("command adapter: acceptable exit code",
				"scanner", a.Name(), "code", exitErr.ExitCode())
		} else {
			return nil, fmt.Errorf("scanner %s: %w (stderr: %s)", a.Name(), runErr,
				truncateForLog(stderr.String(), 2048))
		}
	}

	st, err := os.Stat(outPath)
	if err == nil && st.Size() > maxStdoutBytes {
		return nil, fmt.Errorf("scanner %s: output exceeded %d byte cap (file %d bytes) — execution refused",
			a.Name(), maxStdoutBytes, st.Size())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("scanner %s: read output file: %w", a.Name(), err)
	}

	result := &scanners.ScanResult{RawOutput: raw}
	if a.parser != nil {
		parsed, err := a.parser.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("scanner %s: parse output: %w", a.Name(), err)
		}
		result.Assets = parsed.Assets
		result.Findings = parsed.Findings
		result.Errors = parsed.Errors
	}
	return result, nil
}

func (a *Adapter) exitAcceptable(code int) bool {
	if code == 0 {
		return true
	}
	for _, c := range a.manifest.Configuration.AcceptableExitCodes {
		if c == code {
			return true
		}
	}
	return false
}

// baseEnvKeys are always passed through so tools can start.
var baseEnvKeys = []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "LOGNAME", "SHELL"}

// buildEnv assembles the child environment from the base keys plus the
// manifest allowlist. Everything else is withheld.
func buildEnv(allowlist []string) []string {
	want := map[string]bool{}
	for _, k := range baseEnvKeys {
		want[k] = true
	}
	for _, k := range allowlist {
		want[k] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if want[k] {
			env = append(env, kv)
		}
	}
	return env
}

// truncWriter keeps the first limit bytes and reports truncation.
type truncWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *truncWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if len(p) > remaining {
		if remaining > 0 {
			w.buf.Write(p[:remaining])
		}
		w.truncated = true
		return len(p), nil // io.Writer contract: claim all consumed
	}
	return w.buf.Write(p)
}

func (w *truncWriter) String() string {
	if w.truncated {
		return w.buf.String() + "\n… stderr truncated …"
	}
	return w.buf.String()
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// cappedWriter writes at most limit bytes total (SEC-011); excess is
// silently consumed so the child process never blocks on a full disk.
type cappedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > w.remaining {
		if _, err := w.w.Write(p[:w.remaining]); err != nil {
			return 0, err
		}
		w.remaining = 0
		return len(p), nil // claim everything (io.Writer contract)
	}
	w.remaining -= int64(len(p))
	return w.w.Write(p)
}
