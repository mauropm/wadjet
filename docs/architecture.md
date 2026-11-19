# WADJET Architecture

👁️ *We see what your assets are hiding.*

## Design goals

1. **Modular monolith** — one deployable Go binary, clear module boundaries, dependency injection at `cmd/server`.
2. **Persistence everywhere** — projects, assets, observations, findings, reports, and audit entries survive restarts. Generated PDFs live on a configured filesystem directory and re-download without regeneration.
3. **Genuinely extensible scanning** — adding a security tool must not require touching the orchestrator, the API, or the frontend logic.
4. **Security as architecture** — the scanner allowlist gate, argv-only execution, and untrusted-output handling are structural properties, not per-feature concerns.

## Module map

| Module | Responsibility | Depends on |
|---|---|---|
| `internal/config` | env configuration | — |
| `internal/database` | pgx pool, migration runner | migrations |
| `internal/models` | shared domain types (integration contract) | — |
| `internal/auth` | bcrypt hashing, DB session tokens | database |
| `internal/audit` | append-only action log | database |
| `internal/events` | in-process pub/sub bus → SSE | — |
| `internal/api` | chi router, middleware (auth, rate limit, CORS-dev), JSON envelope | auth, audit, events |
| `internal/projects` | project CRUD, archive, **clone** | database, audit |
| `internal/targets` | scope allowlist, `Authorize()` security gate | database |
| `internal/assets` | inventory + append-only `asset_observations` | database |
| `internal/findings` | normalization, fingerprints, dedup, lifecycle, **ResultSink** | database, assets, audit |
| `internal/profiles` | scan profiles + per-scanner config bindings | database |
| `internal/scanners` | scanner contracts (interface, request/result models) — owned by lead | models |
| `internal/scanners/manifest` | YAML manifest load + validation → `scanners` table | database |
| `internal/scanners/registry` | runtime registry, health checks, enable/disable | manifest |
| `internal/scanners/adapters/command` | external process adapter (exec.CommandContext) | — |
| `internal/scanners/nmap` | argv allowlist builder + XML parser + classifier | command adapter |
| `internal/scanners/nativeprobe` | native Go example adapter (TCP probe) | — |
| `internal/orchestration` | session lifecycle, concurrency, cancellation, raw-output storage | scanners, events |
| `internal/scans` | scan session HTTP surface | orchestration |
| `internal/reports` | gofpdf renderers, async generation, ZIP, download | database, events, audit |

## Scan data flow (the critical path)

```text
POST /scans/{id}/start
   │
   v
scans.Service ──▶ orchestration.Runner (async goroutine)
   │                 │
   │                 ├─ targets.Authorize(project, target)   ← security gate, per target
   │                 ├─ normalize: CIDR expansion (≤1024), DNS (5s)
   │                 ├─ for each scanner (semaphore, timeout ctx):
   │                 │     scanner.Execute()                 ← exec.CommandContext, argv only
   │                 │     persist raw XML → WADJET_RAW_OUTPUT_DIR/<session>/<exec>.xml
   │                 │     findings.Service.Ingest()         ← ONE transaction:
   │                 │         assets.UpsertFromScan()       (upsert asset + append observation)
   │                 │         finding UPSERT ON CONFLICT (project_id, asset_id, fingerprint)
   │                 │         append finding_observations   (append-only detection history)
   │                 │         counters → scan_sessions
   │                 │     bus.Publish(scan.progress)        ← SSE live progress
   │                 └─ session status: completed | completed_with_errors | cancelled
   v
Frontend EventSource(/api/v1/events) re-renders live
```

Failure isolation: one scanner failing never discards sibling results; one
malformed target never aborts an execution.

## Key decisions

**Why no queue infrastructure (Redis/Kafka)?** Scan and report workloads are
in-process goroutines bounded by semaphores. A single-node self-hosted tool
does not need distributed queues; the `scan_sessions`/`scanner_executions`
rows already provide durability and restart-safe visibility. Revisit only if
multi-node execution is ever required.

**Why raw output on disk, not in the DB?** Nmap XML can be tens of MB. The DB
stores the path + byte count in `scanner_executions.raw_output_path`; the
filesystem under `WADJET_RAW_OUTPUT_DIR` is the audit artifact. Parsers must
never emit unsanitized output to the frontend — it is rendered as escaped
monospace text only.

**Why fingerprint dedup instead of CVE identity?** Not every finding has a
CVE. The fingerprint hashes `{scanner, normalized title, port, protocol}`; the
unique key `(project_id, asset_id, fingerprint)` makes re-detection an UPSERT,
while `finding_observations` preserves every detection event with full raw
evidence. `first_detected` never moves backwards; `last_detected` advances.

**Re-detection verification policy:** a finding not seen in a later scan is
**not** auto-remediated (absence of evidence is not evidence of absence —
the scan may have been narrower). Re-appearance of a `remediated` finding
reopens it to `open` with a status-history note.

**Why no DB triggers/stored procedures?** Portability, testability, and one
language for business logic. Uniqueness is enforced by constraints, but every
derived value (counters, `last_detected`, `updated_at`, identity normalization)
is computed in Go inside explicit transactions.

**Scanner extension contract:** YAML manifest (declarative CLI tools) →
`adapters/command`, or Go type implementing `scanners.Scanner` →
`registry.Register`. The UI renders per-scanner configuration forms purely
from `manifest.configuration.options`; no frontend change is needed for a new
scanner with a manifest.

## Security architecture

- **Scope gate:** every target passes `targets.Authorize` against explicit
  include/exclude rows before any process spawns. Exclusions win.
- **Command execution:** argv built from allowlisted flag fragments; user
  option values validated against strict regexes (script names, port ranges)
  before entering argv; executable path comes only from validated manifests;
  `exec.CommandContext` with timeout + cancellation; scanner processes are
  plain children (containerized deployment runs them as an unprivileged user).
- **Output handling:** all scanner text is stored verbatim for audit but
  sanitized (length caps, control-character stripping, non-latin1 folding)
  before PDF or HTML-escaped UI rendering.
- **API surface:** session tokens (bcrypt + SHA-256-hashed DB sessions),
  per-IP token-bucket rate limits, project isolation on every query path,
  audit log on mutations, 1 MiB request bodies.
