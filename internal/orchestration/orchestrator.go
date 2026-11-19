// Package orchestration executes scan sessions asynchronously: it marks
// sessions queued→running, creates scanner_executions rows, executes each
// scanner under a concurrency semaphore and per-execution timeout, enforces
// the project target allowlist, persists raw output, ingests results through
// the ResultSink, and publishes SSE events per the CONTRACTS.md wire format.
package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/mauropm/wadjet/internal/database"
	"github.com/mauropm/wadjet/internal/events"
	"github.com/mauropm/wadjet/internal/models"
	"github.com/mauropm/wadjet/internal/scanners"
	"github.com/mauropm/wadjet/internal/scanners/manifest"
)

// ScannerRegistry is the orchestrator's view of the scanner registry.
type ScannerRegistry interface {
	// Get returns an executable (registered + enabled + available) scanner.
	Get(name string) (scanners.Scanner, bool)
	// Manifest returns the loaded manifest for a registered scanner.
	Manifest(name string) (*manifest.Manifest, bool)
}

// Options configures an Orchestrator.
type Options struct {
	// Concurrency bounds simultaneously executing scanner executions.
	Concurrency int
	// DefaultTimeout applies when neither the manifest nor the request
	// supplies one.
	DefaultTimeout time.Duration
	// RawOutputDir roots raw scanner output storage:
	// <RawOutputDir>/<session-id>/<execution-id>.<ext>.
	RawOutputDir string
	// WorkDir roots per-execution private working directories:
	// <WorkDir>/<session-id>/<execution-id>.
	WorkDir string
	// Normalizer overrides the default target normalizer (tests).
	Normalizer *TargetNormalizer
	// MaxAggregateTargets bounds the total expanded exec-target count across
	// ALL session targets (SEC-008). Default 10000.
	MaxAggregateTargets int
}

// IPExcluder is an optional capability of a TargetAuthorizer: check whether
// a resolved address falls in the project's excluded entries (SEC-004).
type IPExcluder interface {
	IsIPExcluded(ctx context.Context, projectID uuid.UUID, addr netip.Addr) (bool, error)
}

// Orchestrator runs scan sessions.
type Orchestrator struct {
	db         *database.DB
	registry   ScannerRegistry
	sink       scanners.ResultSink
	bus        *events.Bus
	authorizer TargetAuthorizer
	ipExcluder IPExcluder
	opts       Options
	sem        chan struct{}

	mu      sync.Mutex
	cancels map[uuid.UUID]context.CancelFunc
	wg      sync.WaitGroup
}

// New creates an Orchestrator. authorizer may be nil to allow all targets
// (development only). bus may be nil to disable SSE publishing.
func New(db *database.DB, registry ScannerRegistry, sink scanners.ResultSink,
	bus *events.Bus, authorizer TargetAuthorizer, opts Options) *Orchestrator {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.DefaultTimeout <= 0 {
		opts.DefaultTimeout = 30 * time.Minute
	}
	if opts.RawOutputDir == "" {
		opts.RawOutputDir = "./data/raw"
	}
	if opts.WorkDir == "" {
		opts.WorkDir = "./data/scanwork"
	}
	if opts.Normalizer == nil {
		opts.Normalizer = &TargetNormalizer{}
	}
	o := &Orchestrator{
		db: db, registry: registry, sink: sink, bus: bus, authorizer: authorizer,
		opts: opts, sem: make(chan struct{}, opts.Concurrency),
		cancels: map[uuid.UUID]context.CancelFunc{},
	}
	if ex, ok := authorizer.(IPExcluder); ok {
		o.ipExcluder = ex
	}
	return o
}

// StartSession validates a queued session and runs it asynchronously. The
// call returns once the session has been marked running.
func (o *Orchestrator) StartSession(ctx context.Context, sessionID uuid.UUID) error {
	var (
		projectID   uuid.UUID
		rawTargets  []string
		scannerName string
	)
	err := o.db.QueryRow(ctx, `
		UPDATE scan_sessions
		SET status = 'running', started_at = COALESCE(started_at, now()), updated_at = now()
		WHERE id = $1 AND status = 'queued'
		RETURNING project_id, targets, COALESCE(name,'')`, sessionID,
	).Scan(&projectID, &rawTargets, &scannerName)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("orchestration: session %s is not queued (already started, cancelled or missing)", sessionID)
	}
	if err != nil {
		return fmt.Errorf("orchestration: start session: %w", err)
	}

	o.publish(KindScanStatus, ScanStatusEvent{SessionID: sessionID, Status: models.ScanStatusRunning})

	o.wg.Add(1)
	go o.runSession(sessionID, projectID, rawTargets)
	return nil
}

// Cancel requests cancellation of a running session. Returns false when the
// session is not currently executing in this process.
func (o *Orchestrator) Cancel(sessionID uuid.UUID) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	cancel, ok := o.cancels[sessionID]
	if !ok {
		return false
	}
	cancel()
	return true
}

// Wait blocks until every asynchronously started session has finished.
// Used by tests and graceful shutdown.
func (o *Orchestrator) Wait() { o.wg.Wait() }

func (o *Orchestrator) registerCancel(sessionID uuid.UUID, cancel context.CancelFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cancels[sessionID] = cancel
}

func (o *Orchestrator) unregisterCancel(sessionID uuid.UUID) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.cancels, sessionID)
}

// runSession is the async driver: never panics, never aborts sibling
// executions, always keeps already-collected results.
func (o *Orchestrator) runSession(sessionID, projectID uuid.UUID, rawTargets []string) {
	defer o.wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.registerCancel(sessionID, cancel)
	defer o.unregisterCancel(sessionID)

	started := time.Now()

	// ── 1. authorize + normalize targets ────────────────────────────────
	var execTargets []scanners.Target
	var approvedRaw []string
	for _, raw := range rawTargets {
		if err := o.authorize(ctx, projectID, raw); err != nil {
			o.markTarget(sessionID, raw, "denied", err.Error())
			slog.Warn("orchestration: target denied by allowlist",
				"session", sessionID.String(), "target", raw, "err", err)
			continue
		}
		norm := o.opts.Normalizer.Normalize(ctx, projectID, raw)
		if norm.Err != "" {
			o.markTarget(sessionID, raw, "failed", norm.Err)
			continue
		}
		// SECURITY (SEC-004): the allowlist authorizes text; scanners resolve
		// names themselves. Re-check every resolved address against the same
		// allowlist so a DNS-rebinding name cannot smuggle a scan through an
		// excluded or unauthorized IP, and hard-block link-local/metadata
		// ranges (an explicit IP target entry remains the escape hatch).
		if len(norm.ResolvedIPs) > 0 {
			if err := o.checkResolvedIPs(ctx, projectID, raw, norm.ResolvedIPs); err != nil {
				o.markTarget(sessionID, raw, "denied", err.Error())
				slog.Warn("orchestration: target denied via resolved-address re-check",
					"session", sessionID.String(), "target", raw, "err", err)
				continue
			}
		}
		o.markTarget(sessionID, raw, "pending", "")
		approvedRaw = append(approvedRaw, raw)
		if len(norm.ResolvedIPs) > 0 {
			slog.Info("orchestration: target resolved",
				"session", sessionID.String(), "target", raw, "ips", norm.ResolvedIPs)
		}
		execTargets = append(execTargets, norm.ExecTargets...)
		// SECURITY (SEC-008): budget aggregate expansion across ALL targets
		// so many small CIDRs cannot stack into an unbounded scan.
		if len(execTargets) > o.maxAggregateTargets() {
			o.finishSession(sessionID, started, models.ScanStatusFailed,
				fmt.Sprintf("aggregate target budget exceeded (%d hosts; limit %d)",
					len(execTargets), o.maxAggregateTargets()))
			return
		}
	}

	// ── 2. executions ───────────────────────────────────────────────────
	if len(execTargets) == 0 {
		o.finishSession(sessionID, started, models.ScanStatusFailed,
			"no targets remained after allowlist validation and normalization")
		return
	}
	execs, err := o.loadOrPrepareExecutions(context.WithoutCancel(ctx), sessionID, projectID, approvedRaw)
	if err != nil {
		o.finishSession(sessionID, started, models.ScanStatusFailed, err.Error())
		return
	}
	if len(execs) == 0 {
		o.finishSession(sessionID, started, models.ScanStatusFailed,
			"session has no scanner executions")
		return
	}

	// ── 3. execute, honoring the semaphore; failures are per-execution ──
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		anyFail  bool
		anyCanc  bool
		assets   int
		findings int
	)
	for _, ex := range execs {
		if ex.Status != models.ExecStatusQueued {
			continue // already run (e.g. resumed after cancel is not supported)
		}
		wg.Add(1)
		go func(ex models.ScannerExecution) {
			defer wg.Done()
			o.sem <- struct{}{}
			defer func() { <-o.sem }()

			status, assetsObs, findingsFound, _ := o.runExecution(ctx, sessionID, projectID, ex, execTargets)
			mu.Lock()
			switch status {
			case models.ExecStatusFailed:
				anyFail = true
			case models.ExecStatusCancelled:
				anyCanc = true
			}
			assets += assetsObs
			findings += findingsFound
			cumAssets, cumFindings := assets, findings
			mu.Unlock()
			if status == models.ExecStatusCompleted {
				// Cumulative session progress per the SSE wire contract.
				o.publish(KindScanProgress, ScanProgressEvent{
					SessionID:       sessionID,
					AssetsProcessed: cumAssets,
					FindingsCreated: cumFindings,
				})
			}
		}(ex)
	}
	wg.Wait()

	// ── 4. finalize session ─────────────────────────────────────────────
	final := models.ScanStatusCompleted
	errMsg := ""
	switch {
	case anyCanc:
		final = models.ScanStatusCancelled
	case anyFail:
		final = models.ScanStatusCompletedWithErrors
	}
	// VER-001: findings.Service.Ingest is the single writer of session
	// counters when a sink is configured; orchestrator only counts when it
	// is running without ingestion (development/test mode).
	if o.sink == nil {
		o.updateSessionCounters(sessionID, assets, findings)
	}
	o.finishSession(sessionID, started, final, errMsg)

	if final == models.ScanStatusCompleted || final == models.ScanStatusCompletedWithErrors {
		o.markTargetsFinal(sessionID, "completed")
	}
}

func (o *Orchestrator) authorize(ctx context.Context, projectID uuid.UUID, target string) error {
	if o.authorizer == nil {
		return nil
	}
	return o.authorizer.Authorize(ctx, projectID, target)
}

// linkLocalBlocklists are ranges a hostname must never resolve to for
// scanning purposes (cloud metadata, link-local). Explicit IP target
// entries still authorize themselves.
var linkLocalBlocklists = []string{"169.254.0.0/16", "fe80::/10", "fc00::/7", "0.0.0.0/8"}

var linkLocalNets = func() []*netip.Prefix {
	var out []*netip.Prefix
	for _, c := range linkLocalBlocklists {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, &p)
		}
	}
	return out
}()

// checkResolvedIPs re-checks DNS answers against the project's exclusions
// and hard-blocked ranges (SEC-004). Authorizing a hostname textually must
// not let DNS answers inside an excluded CIDR (or cloud metadata ranges)
// through. The narrow TOCTOU window between this check and the scanner's
// own resolution is documented residual risk.
func (o *Orchestrator) checkResolvedIPs(ctx context.Context, projectID uuid.UUID, raw string, ips []string) error {
	for _, ipStr := range ips {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("target %s: resolver returned unparseable address %q", raw, ipStr)
		}
		addr = addr.Unmap()
		for _, blk := range linkLocalNets {
			if blk.Contains(addr) {
				return fmt.Errorf("target %s: resolved address %s is in blocked range %s", raw, ipStr, blk)
			}
		}
		if o.ipExcluder != nil {
			excluded, err := o.ipExcluder.IsIPExcluded(ctx, projectID, addr)
			if err != nil {
				return fmt.Errorf("target %s: exclusion check for %s failed: %w", raw, ipStr, err)
			}
			if excluded {
				return fmt.Errorf("target %s: resolved address %s matches an excluded entry", raw, ipStr)
			}
		}
	}
	return nil
}

func (o *Orchestrator) maxAggregateTargets() int {
	if o.opts.MaxAggregateTargets > 0 {
		return o.opts.MaxAggregateTargets
	}
	return 10000
}

// RecoverInterrupted fails sessions/executions left mid-flight by a previous
// process (VER-006): a server that died mid-scan must not resurrect phantom
// running rows. Call once at boot before serving traffic.
func (o *Orchestrator) RecoverInterrupted(ctx context.Context) error {
	bg, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := o.db.Exec(bg, `
		UPDATE scanner_executions
		SET status = 'failed', error = 'interrupted by server restart', finished_at = now()
		WHERE status IN ('running','queued')`)
	if err != nil {
		return fmt.Errorf("recover interrupted executions: %w", err)
	}
	_, err = o.db.Exec(bg, `
		UPDATE scan_sessions
		SET status = 'failed', error = 'interrupted by server restart',
		    finished_at = now(), updated_at = now()
		WHERE status IN ('running','queued')`)
	if err != nil {
		return fmt.Errorf("recover interrupted sessions: %w", err)
	}
	return nil
}

// ValidateTargets checks every target against the project's authorization
// allowlist up front (defense-in-depth: the same gate runs again at
// execution time). It returns the first authorization failure.
func (o *Orchestrator) ValidateTargets(ctx context.Context, projectID uuid.UUID, targets []string) error {
	for _, t := range targets {
		if err := o.authorize(ctx, projectID, t); err != nil {
			return fmt.Errorf("target %s: %w", t, err)
		}
	}
	return nil
}

// execution is one scanner_executions row to run.
func (o *Orchestrator) runExecution(sessionCtx context.Context, sessionID, projectID uuid.UUID,
	ex models.ScannerExecution, targets []scanners.Target) (status string, assetsObs, findingsFound int, errMsg string) {

	// Deterministic cancellation: if the session was cancelled during target
	// preparation (before this goroutine ran), record the terminal state now
	// instead of racing the scanner's own ctx handling.
	if sessionCtx.Err() != nil {
		o.persistExecutionTerminal(ex.ID, models.ExecStatusCancelled, "", 0, 0, 0, "cancelled before execution", "")
		o.publish(KindExecutionStatus, ExecutionStatusEvent{
			SessionID: sessionID, ExecutionID: ex.ID, Scanner: ex.ScannerName,
			Status: models.ExecStatusCancelled, Error: "cancelled before execution",
		})
		return models.ExecStatusCancelled, 0, 0, "cancelled before execution"
	}

	scanner, ok := o.registry.Get(ex.ScannerName)
	if !ok {
		msg := fmt.Sprintf("scanner %q is not registered, enabled or available", ex.ScannerName)
		o.persistExecutionFailed(ex.ID, msg)
		o.publish(KindExecutionStatus, ExecutionStatusEvent{
			SessionID: sessionID, ExecutionID: ex.ID, Scanner: ex.ScannerName,
			Status: models.ExecStatusFailed, Error: msg,
		})
		return models.ExecStatusFailed, 0, 0, msg
	}

	var config scanners.ScannerConfig
	if len(ex.Config) > 0 {
		if err := json.Unmarshal(ex.Config, &config); err != nil {
			msg := fmt.Sprintf("invalid execution config: %v", err)
			o.persistExecutionFailed(ex.ID, msg)
			return models.ExecStatusFailed, 0, 0, msg
		}
	}

	timeout := o.opts.DefaultTimeout
	if m, ok := o.registry.Manifest(ex.ScannerName); ok {
		timeout = time.Duration(m.TimeoutSeconds()) * time.Second
	}

	execCtx, cancel := context.WithTimeout(sessionCtx, timeout)
	defer cancel()

	workDir := filepath.Join(o.opts.WorkDir, sessionID.String(), ex.ID.String())
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		msg := fmt.Sprintf("create work dir: %v", err)
		o.persistExecutionFailed(ex.ID, msg)
		return models.ExecStatusFailed, 0, 0, msg
	}

	if _, err := o.db.Exec(execCtx, `
		UPDATE scanner_executions
		SET status='running', started_at = now(), error = ''
		WHERE id = $1`, ex.ID); err != nil {
		slog.Warn("orchestration: mark execution running", "err", err)
	}
	o.publish(KindExecutionStatus, ExecutionStatusEvent{
		SessionID: sessionID, ExecutionID: ex.ID, Scanner: ex.ScannerName,
		Status: models.ExecStatusRunning,
	})

	req := scanners.ScanRequest{
		SessionID:   sessionID,
		ExecutionID: ex.ID,
		ProjectID:   projectID,
		Targets:     targets,
		Config:      config,
		WorkDir:     workDir,
		Timeout:     timeout,
	}

	result, runErr := scanner.Execute(execCtx, req)
	if runErr != nil {
		status := models.ExecStatusFailed
		if errors.Is(execCtx.Err(), context.Canceled) && sessionCtx.Err() != nil {
			status = models.ExecStatusCancelled
		}
		msg := runErr.Error()
		if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			msg = fmt.Sprintf("timed out after %s: %s", timeout, msg)
		}
		msg = truncate(msg, 4096)
		o.persistExecutionTerminal(ex.ID, status, "", 0, 0, 0, msg, "")
		o.publish(KindExecutionStatus, ExecutionStatusEvent{
			SessionID: sessionID, ExecutionID: ex.ID, Scanner: ex.ScannerName,
			Status: status, Error: msg,
		})
		return status, 0, 0, msg
	}

	// Persist raw output — always kept, even if ingestion later fails.
	rawPath, rawBytes, logNote := "", int64(0), buildErrorNote(result)
	if len(result.RawOutput) > 0 {
		ext := "out"
		if m, ok := o.registry.Manifest(ex.ScannerName); ok {
			ext = m.DefaultExtension()
		}
		dir := filepath.Join(o.opts.RawOutputDir, sessionID.String())
		path := filepath.Join(dir, ex.ID.String()+"."+ext)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			slog.Error("orchestration: cannot create raw output dir", "dir", dir, "err", err)
			msg := fmt.Sprintf("persist raw output: %v", err)
			o.persistExecutionTerminal(ex.ID, models.ExecStatusFailed, "", 0, 0, 0, msg, "")
			return models.ExecStatusFailed, 0, 0, msg
		}
		if err := os.WriteFile(path, result.RawOutput, 0o640); err != nil {
			msg := fmt.Sprintf("write raw output: %v", err)
			o.persistExecutionTerminal(ex.ID, models.ExecStatusFailed, "", 0, 0, 0, msg, "")
			return models.ExecStatusFailed, 0, 0, msg
		}
		rawPath, rawBytes = path, int64(len(result.RawOutput))
	}

	assetsObs = len(result.Assets)
	findingsFound = len(result.Findings)

	// Ingest through the sink with its own deadline: a hung ingest must not
	// outlive the scan timeout context.
	if o.sink != nil {
		ingestCtx, ingestCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := o.sink.Ingest(ingestCtx, sessionID, ex.ID, ex.ScannerName, result)
		ingestCancel()
		if err != nil {
			msg := fmt.Sprintf("result ingestion failed (raw output preserved): %v", err)
			o.persistExecutionTerminal(ex.ID, models.ExecStatusFailed, rawPath, rawBytes, assetsObs, findingsFound, msg, "")
			o.publish(KindExecutionStatus, ExecutionStatusEvent{
				SessionID: sessionID, ExecutionID: ex.ID, Scanner: ex.ScannerName,
				Status: models.ExecStatusFailed, AssetsObserved: assetsObs,
				FindingsFound: findingsFound, Error: msg,
			})
			return models.ExecStatusFailed, assetsObs, findingsFound, msg
		}
	}

	status = models.ExecStatusCompleted
	o.persistExecutionTerminal(ex.ID, status, rawPath, rawBytes, assetsObs, findingsFound, "", logNote)
	o.publish(KindExecutionStatus, ExecutionStatusEvent{
		SessionID: sessionID, ExecutionID: ex.ID, Scanner: ex.ScannerName,
		Status: status, AssetsObserved: assetsObs, FindingsFound: findingsFound,
	})
	return status, assetsObs, findingsFound, ""
}

// ── persistence helpers ─────────────────────────────────────────────────

func (o *Orchestrator) persistExecutionFailed(execID uuid.UUID, msg string) {
	o.persistExecutionTerminal(execID, models.ExecStatusFailed, "", 0, 0, 0, msg, "")
}

// persistExecutionTerminal writes the terminal state of one execution. It
// uses a detached context because terminal bookkeeping must survive
// cancellation or timeout of the execution itself.
func (o *Orchestrator) persistExecutionTerminal(execID uuid.UUID,
	status, rawPath string, rawBytes int64, assets, findings int, errMsg string, logNote string) {
	bg, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := o.db.Exec(bg, `
		UPDATE scanner_executions
		SET status = $2, raw_output_path = $3, raw_output_bytes = $4,
		    assets_observed = $5, findings_found = $6, error = $7,
		    log = CASE WHEN $8 = '' THEN log ELSE $8 END,
		    finished_at = now()
		WHERE id = $1`,
		execID, status, rawPath, rawBytes, assets, findings, truncate(errMsg, 4096), logNote)
	if err != nil {
		slog.Error("orchestration: persist execution terminal state",
			"execution", execID.String(), "err", err)
	}
}

func (o *Orchestrator) markTarget(sessionID uuid.UUID, target, status, errMsg string) {
	bg, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := o.db.Exec(bg, `
		INSERT INTO scan_session_targets (session_id, target, status, error)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (session_id, target) DO UPDATE SET status = EXCLUDED.status, error = EXCLUDED.error`,
		sessionID, target, status, truncate(errMsg, 1024))
	if err != nil {
		slog.Error("orchestration: mark target", "err", err)
	}
}

func (o *Orchestrator) markTargetsFinal(sessionID uuid.UUID, status string) {
	bg, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := o.db.Exec(bg, `
		UPDATE scan_session_targets SET status = $2
		WHERE session_id = $1 AND status IN ('pending','running')`, sessionID, status)
	if err != nil {
		slog.Error("orchestration: finalize targets", "err", err)
	}
}

func (o *Orchestrator) updateSessionCounters(sessionID uuid.UUID, assets, findings int) {
	bg, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := o.db.Exec(bg, `
		UPDATE scan_sessions
		SET assets_processed = assets_processed + $2,
		    findings_created = findings_created + $3,
		    updated_at = now()
		WHERE id = $1`, sessionID, assets, findings)
	if err != nil {
		slog.Error("orchestration: update session counters", "err", err)
	}
}

func (o *Orchestrator) finishSession(sessionID uuid.UUID, started time.Time, status, errMsg string) {
	dur := time.Since(started).Milliseconds()
	bg, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := o.db.Exec(bg, `
		UPDATE scan_sessions
		SET status = $2, error = $3, finished_at = now(), duration_ms = $4, updated_at = now()
		WHERE id = $1`, sessionID, status, truncate(errMsg, 4096), dur); err != nil {
		slog.Error("orchestration: finalize session", "session", sessionID.String(), "err", err)
	}
	o.publish(KindScanStatus, ScanStatusEvent{SessionID: sessionID, Status: status, Error: errMsg})
}

// loadOrPrepareExecutions returns the session's executions, creating rows
// from the session snapshot when the API layer has not pre-created them.
// Config resolution order: existing row → profile binding → project scanner
// configuration → {}.
func (o *Orchestrator) loadOrPrepareExecutions(ctx context.Context, sessionID, projectID uuid.UUID, approvedRaw []string) ([]models.ScannerExecution, error) {
	execs, err := o.loadExecutions(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if len(execs) > 0 {
		// Keep execution targets aligned with the authorized set.
		for i := range execs {
			execs[i].Targets = approvedRaw
		}
		return execs, nil
	}

	var profileID *uuid.UUID
	var scannerNames []string
	if err := o.db.QueryRow(ctx,
		`SELECT profile_id, scanner_names FROM scan_sessions WHERE id = $1`, sessionID,
	).Scan(&profileID, &scannerNames); err != nil {
		return nil, fmt.Errorf("orchestration: load session snapshot: %w", err)
	}
	if approvedRaw == nil {
		approvedRaw = []string{}
	}

	for _, name := range scannerNames {
		if _, ok := o.registry.Manifest(name); !ok {
			// Registered later? Skip with a recorded execution failure.
			_, _ = o.db.Exec(ctx, `
				INSERT INTO scanner_executions (session_id, scanner_name, status, error, targets)
				VALUES ($1,$2,'failed','not registered in the scanner registry',$3)
				ON CONFLICT DO NOTHING`, sessionID, name, approvedRaw)
			continue
		}
		config := o.resolveConfig(ctx, profileID, projectID, name)
		if _, err := o.db.Exec(ctx, `
			INSERT INTO scanner_executions (session_id, scanner_name, status, config, targets)
			VALUES ($1,$2,'queued',$3,$4)
			ON CONFLICT DO NOTHING`, sessionID, name, config, approvedRaw); err != nil {
			return nil, fmt.Errorf("orchestration: create execution for %s: %w", name, err)
		}
	}
	return o.loadExecutions(ctx, sessionID)
}

func (o *Orchestrator) resolveConfig(ctx context.Context, profileID *uuid.UUID, projectID uuid.UUID, name string) json.RawMessage {
	var raw []byte
	var err error
	if profileID != nil {
		err = o.db.QueryRow(ctx, `
			SELECT ps.config FROM scan_profile_scanners ps
			JOIN scanners s ON s.id = ps.scanner_id
			WHERE ps.profile_id = $1 AND s.name = $2`, *profileID, name).Scan(&raw)
		if err == nil && len(raw) > 0 {
			return raw
		}
	}
	err = o.db.QueryRow(ctx, `
		SELECT sc.config FROM scanner_configurations sc
		JOIN scanners s ON s.id = sc.scanner_id
		WHERE sc.project_id = $1 AND s.name = $2`, projectID, name).Scan(&raw)
	if err == nil && len(raw) > 0 {
		return raw
	}
	return json.RawMessage(`{}`)
}

func (o *Orchestrator) loadExecutions(ctx context.Context, sessionID uuid.UUID) ([]models.ScannerExecution, error) {
	rows, err := o.db.Query(ctx, `
		SELECT id, session_id, scanner_name, status, config, targets,
		       raw_output_path, raw_output_bytes, assets_observed, findings_found,
		       error, log, started_at, finished_at, created_at
		FROM scanner_executions WHERE session_id = $1 ORDER BY created_at, scanner_name`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("orchestration: load executions: %w", err)
	}
	defer rows.Close()
	var out []models.ScannerExecution
	for rows.Next() {
		var ex models.ScannerExecution
		if err := rows.Scan(&ex.ID, &ex.SessionID, &ex.ScannerName, &ex.Status, &ex.Config,
			&ex.Targets, &ex.RawOutputPath, &ex.RawOutputBytes, &ex.AssetsObserved,
			&ex.FindingsFound, &ex.Error, &ex.Log, &ex.StartedAt, &ex.FinishedAt, &ex.CreatedAt); err != nil {
			return nil, fmt.Errorf("orchestration: scan execution: %w", err)
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

func buildErrorNote(result *scanners.ScanResult) string {
	if result == nil || len(result.Errors) == 0 {
		return ""
	}
	out := "per-target errors:"
	for i, e := range result.Errors {
		if i >= 32 {
			out += fmt.Sprintf("\n…and %d more", len(result.Errors)-i)
			break
		}
		out += fmt.Sprintf("\n- [%s] %s", e.Target, e.Error)
	}
	return truncate(out, 16*1024)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
