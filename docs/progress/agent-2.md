# Agent 2 — Scanner Engine / Security Research — Progress

Status: COMPLETE
Last update: 2026-11-19

## Deliverables

| # | Deliverable | Status |
|---|---|---|
| 1 | `internal/scanners/manifest` — YAML loader + strict validator + shared config-validation engine | ✅ done, 100+ validation cases |
| 2 | `internal/scanners/registry` — Load/Get/List/Enable/Disable/CheckAvailability, scanners-table UPSERT (manifest JSONB, status from executable lookup) | ✅ done, DB tests |
| 3 | `internal/scanners/adapters/command` — generic secure exec.CommandContext adapter (argv templates, env allowlist, exit-code policy, stdout→file, stderr→truncated log, cancellation) | ✅ done, incl. real /bin/echo, /usr/bin/false, cancellation tests |
| 4 | `internal/scanners/nmap` — allowlist-driven argv, XML parser, curated script→finding classifier | ✅ done; **real nmap 7.993 integration tests pass on loopback** |
| 5 | `internal/orchestration` — async sessions, semaphore, per-exec timeout, cancel registry, TargetAuthorizer, CIDR cap 1024, DNS 5s, raw output persistence, ResultSink, SSE per wire contract | ✅ done, DB-backed lifecycle tests |
| 6 | `internal/scans` — chi REST service (scans + scanners routes, SSE /scans/{id}/events) | ✅ done, httptest suite |
| 7 | `configs/scanners/{nmap,nuclei,nativeprobe}.yaml` + native TCP probe scanner | ✅ done |
| 8 | `docs/scanner-development.md` | ✅ done |

## Test results (local, 2026-11-19)

```
go build ./...                                   clean
go vet ./internal/scanners/... ./internal/orchestration/... ./internal/scans/...   clean
gofmt -l                                         clean
go test ./internal/scanners/... ./internal/orchestration/... ./internal/scans/...
  ok internal/scanners/adapters/command
  ok internal/scanners/manifest
  ok internal/scanners/nativeprobe
  ok internal/scanners/nmap          (incl. real-nmap integration, LookPath-guarded)
  ok internal/scanners/registry      (test DB)
  ok internal/orchestration          (test DB)
  ok internal/scans                  (test DB + httptest)
go test -race nmap/orchestration                 clean
```

## Interfaces exposed for wiring (exact constructors)

Lead wires these in `cmd/server/main.go` (via `api.Registrable`):

```go
import (
    "github.com/mauropm/wadjet/internal/scanners/registry"
    "github.com/mauropm/wadjet/internal/orchestration"
    "github.com/mauropm/wadjet/internal/scans"
)

reg := registry.New(db)                                  // *database.DB
err := reg.Load(ctx, cfg.ScannerCfgDir)                  // configs/scanners
orch := orchestration.New(db, reg, sink, bus,
    authorizer,                                          // agent-3 TargetAuthorizer (nil = allow all)
    orchestration.Options{
        Concurrency:    cfg.ScanConcurrency,
        DefaultTimeout: time.Duration(cfg.ScanTimeout) * time.Second,
        RawOutputDir:   cfg.RawOutputDir,
        WorkDir:        cfg.ScanWorkDir,
    })
scansSvc := scans.NewService(db, reg, orch, bus)         // implements api.Registrable
extra = append(extra, scansSvc)                          // registers scanners+scans routes
```

Agent 3 must implement:

```go
// orchestration.TargetAuthorizer
Authorize(ctx context.Context, projectID uuid.UUID, target string) error
// (error = DENY; session target row recorded 'denied', siblings continue)

// scanners.ResultSink (per CONTRACTS.md §3)
Ingest(ctx context.Context, sessionID, executionID uuid.UUID,
       scannerName string, result *scanners.ScanResult) error
```

## Files created

- internal/scanners/manifest/{manifest.go,config.go,manifest_test.go}
- internal/scanners/registry/{registry.go,probe.go,registry_test.go}
- internal/scanners/adapters/command/{command.go,command_test.go}
- internal/scanners/nmap/{nmap.go,args.go,parser.go,classify.go,
  args_test.go,parser_test.go,classify_test.go,integration_test.go,
  testdata/full.xml,testdata/vulns.xml}
- internal/scanners/nativeprobe/{nativeprobe.go,nativeprobe_test.go}
- internal/orchestration/{orchestrator.go,events.go,targets.go,
  orchestrator_test.go,targets_test.go}
- internal/scans/{service.go,service_test.go}
- configs/scanners/{nmap.yaml,nuclei.yaml,nativeprobe.yaml}
- docs/scanner-development.md, docs/progress/agent-2.md

## Security decisions

- exec.CommandContext only; argv always discrete `[]string`; no shell.
- Executable path only from validated manifest (`^[A-Za-z0-9/][A-Za-z0-9._/+@-]*$`).
- All argv-affecting config values pass strict per-option regexes/allowlists;
  failures abort execution (never sanitized-and-passed). Leading-dash values
  rejected (flag injection). NSE categories exclude intrusive/dos/exploit;
  individual scripts restricted to a curated set.
- Child env: base vars + manifest `env_allowlist` only.
- Findings only from the curated NSE classification table; CVEs extracted
  verbatim from output text; CVSS never fabricated; unmatched scripts stay
  INFO observations in `AssetObservationData.Extra`.
- OS detection (`-O`) degrades gracefully (logged) when unprivileged.
- Injection test matrix covers `; rm -rf`, backticks, `$(id)`, spaces,
  `--evil` targets, glob chars, newlines — all rejected before argv.

## Environment notes / resolved issues

- nmap 7.993 present at /opt/homebrew/bin/nmap (per Lead). Integration tests
  pass; still guarded by `exec.LookPath("nmap")` for CI.
- **Test DB credentials**: the task brief's URL showed the password masked
  (`***`); the literal masked string fails auth. Tests use
  `postgres://wadjet:wadjet@127@127.0.0.1:5432/wadjet` (verified against the
  wadjet-pg container, POSTGRES_PASSWORD=wadjet). 127.0.0.1 pinned to avoid
  flaky IPv6 forwarding through OrbStack with `localhost`.
- `go mod tidy` was run once to activate the Lead-approved deps that were
  pre-seeded in go.sum (gopkg.in/yaml.v3, testify) plus the gofpdf transitive
  entry another agent's go.mod edit required. No `go get` was used; nothing
  outside CONTRACTS.md §2's allowed list entered the graph.

## Contract-change requests

1. **ResultSink counters**: `Ingest` returns only `error`, so the
   orchestrator cannot publish accurate `findings_created` vs
   `findings_updated` in `scan.progress` (it reports detections as created,
   0 updated). Suggested future signature:
   `Ingest(...) (*IngestResult{Assets, Created, Updated int}, error)`.
   Not required for v1; SSE payload shape stays contract-compliant.
2. None blocking.

## Blockers

(none)
