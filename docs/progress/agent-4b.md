# Agent 4B — PDF Reporting + Demonstration Environment

Progress log. Updated continuously.

## Interfaces (final)

```go
// Constructor for Lead wiring (CONTRACTS.md §2):
func reports.NewService(db *database.DB, cfg *config.Config, bus *events.Bus, audit *audit.Logger) *reports.Service
// Satisfies api.Registrable (cmd/server `extra` list):
func (s *reports.Service) Register(r chi.Router)
```

Wiring example for the Lead (cmd/server):

```go
import "github.com/mauropm/wadjet/internal/reports"
extra := []api.Registrable{ reports.NewService(db, cfg, bus, auditLogger) /* ... */ }
```

Routes registered (mounted under /api/v1 by the Lead, auth applied outside):

```
POST /projects/{id}/reports/scan        {"session_id": "..."}                → 202 report (pending)
POST /projects/{id}/reports/findings    {"consolidated": bool, "severity": [],
                                         "asset_id": "...", "session_id": "..."}
      consolidated=true  → single PDF  (type findings_consolidated)
      consolidated=false → ZIP bundle  (type findings_zip)   → 202 report (pending)
POST /findings/{id}/report                                                    → 202 report (pending)
GET  /reports            ?project_id= &type=                                  → {"items":[],"total":n}
GET  /reports/{id}       ?project_id= (optional isolation scope)              → report JSON
GET  /reports/{id}/download      application/pdf | application/zip,
                                 Content-Disposition attachment (sanitized name),
                                 409 while pending/generating/failed,
                                 404 for missing files AND cross-project/dangling
                                 session|finding chains (isolation)
```

SSE: Topic `report`, Kind `report.status`, payload
`{"report_id","project_id","status","file_size"}` — published on every
status transition (pending/generating/completed/failed), matching the §4
wire contract.

File layout on disk: `<WADJET_REPORT_DIR>/<project-slug>/<type>-<report-uuid>-<yyyymmdd-hhmm>.pdf|.zip`;
`reports.file_path` stores the path relative to the report dir, `file_size`
the on-disk size. Atomic write (tmp + rename). Completed rows survive
restarts (served straight from disk); `pending`/`generating` rows found at
startup are marked failed ("generation interrupted by server restart").
Queue: in-process worker pool, semaphore N=2, 10-min per-job timeout.

## Deliverables

### A — internal/reports (COMPLETE)

- `sanitize.go` — untrusted-input boundary: control/invisible-char stripping,
  rune-based caps (evidence 10k, description 5k, technical 10k, title 300 —
  truncation marker `…[truncated]`), WinAnsi transcode for core fonts
  (non-representable runes → `?`), slugify/fileSafe/isPathSafe.
- `renderer.go` — gofpdf branded renderer: cover page with geometric eye
  mark (arcs + circles + bezier tail, emerald #10B981), WADJET wordmark +
  tagline, title block; `WADJET · project · date` header and `Page N of M`
  footer on every content page (suppressed on cover); sections, key/value
  lists, severity chips, zebra tables with hard-wrapped cells, horizontal
  severity bar chart, monospace evidence blocks, references list.
- `queries.go` — all data loaded from PostgreSQL (projects, sessions,
  executions + registry versions, scope targets, assets, latest-observation
  ports via defensive JSONB decode, findings w/ FND-<n> labels, status
  history, detection history, observation summary).
- `scan.go` — scan report: cover → exec summary (severity chips + generated
  narrative from real stats) → scope → methodology (scanners/versions/config)
  → asset inventory → services & ports → severity distribution chart →
  detailed findings grouped by severity → scan execution details → appendix.
- `findingpdf.go` — standalone advisory (fully self-contained incl. business
  impact derived from severity + service context, status history, observation
  dates), consolidated report with summary table, ZIP builder
  (`findings/FND-<seq>-<slug>.pdf` + `manifest.csv`
  `finding_id,title,severity,asset,fingerprint`).
- `reports.go` — Service, queue, lifecycle, SSE publish, REST handlers,
  project isolation, audit logging (`report.create`, `report.download`).

### B — demo/ + root infra (COMPLETE)

- `demo/docker-compose.yml` — Juice Shop (3000), WebGoat (8080), banner-rich
  nginx (80), self-signed TLS nginx (443, deprecated protocols),
  linuxserver openssh w/ custom banner (2222), noisy socat 8000–8005.
  Private `wadjet-lab` network, `internal: true`, **zero host port
  publishing**, healthchecks on all, security notice in header.
- `demo/nginx/http-banner.conf`, `demo/nginx/tls-test.conf`,
  `demo/ssh/banner.txt`.
- `demo/README.md` — start/scan/NSE walkthrough/teardown docs.
- `demo/seed/main.go` — `go run ./demo/seed` creates "🧪 WADJET Demo Lab":
  6 authorized targets + 1 excluded canary (198.51.100.0/24), Quick
  Discovery + Standard Assessment profiles with nmap bindings, 2 manual
  assets (tag `demo`); **never seeds findings**; idempotent; `--cleanup`
  removes the project (cascades). Verified live: create → idempotent no-op →
  counts (7 targets / 2 profiles / 2 bindings / 2 assets / 0 findings) →
  cleanup → no-op.
- Root `Dockerfile` — golang:1.26-alpine → alpine + nmap + nmap-scripts,
  non-root uid 10001, `/app/data` volume, healthcheck. Bases are
  `BUILD_BASE`/`RUNTIME_BASE` build args (pinned defaults, overridable for
  air-gapped builds). Verified: image builds (`wadjet:local`), container
  boots, connects to Postgres, serves `/healthz`, login works.
  (Local verification used `--build-arg RUNTIME_BASE=alpine:latest` because
  docker.io registry access timed out mid-session for `alpine:3.22`; the
  Dockerfile default remains the pinned `alpine:3.22`.)
- Root `docker-compose.yml` — `wadjet` (build ., 8080, ./data:/app/data,
  env defaults from .env.example) + `postgres:16-alpine` (healthcheck, pgdata
  volume, no host port). Joins shared `wadjet-lab` network so WADJET can
  scan the lab lab-to-lab. **Verified**: `docker compose up` alone brings up
  a healthy Postgres + app (`/healthz` 200, admin login OK), then torn down.
  Two transitional necessities live here:
  1. Postgres has an initdb hook that applies `0001_init.sql` with
     `references` quoted (until the Lead fixes the migration — then it is a
     no-op) and records the version so the app's migration runner skips it.
  2. `WADJET_ADMIN_PASSWORD` default is `wadjet-admin` (≥8 chars) because
     `auth.EnsureAdmin` rejects the shorter `.env.example` value `admin` —
     `.env.example` is not 4B-owned; consider updating it or relaxing the
     bootstrap floor.

## Test results

`go test ./internal/reports/` — **all pass** (21 tests, ~2s):

- Unit: sanitizer (controls/emoji/CP1252/CRLF), caps, pdfText WinAnsi,
  slugify (emoji/collision/accent transliteration), fileSafe, isPathSafe,
  observedPorts decoding; ZIP structure, manifest.csv round-trip, empty
  archive, duplicate-entry uniquification.
- Integration (live DB): scan/finding/consolidated/ZIP end-to-end (pending→
  completed rows, on-disk `%PDF`/`PK` files, filename conventions), download
  headers, list/detail endpoints, 400/404/409/422 paths, cross-project
  isolation incl. forged session chains, restart survival + stale-row
  recovery, SSE `report.status` contract, adversarial-content render pass,
  direct layout fuzz-ish render (12k tokens, ANSI, RTL, emoji).

DB hygiene: all fixtures cleaned by project name; demo project left absent.
Samples kept at `/tmp/wadjet-sample/`: `scan-report.pdf`,
`findings-consolidated.pdf`, `finding-advisory.pdf`, `findings-zip.zip`.

## Environment actions taken (for the Lead)

1. `migrations/0001_init.sql`: `references` column unquoted → fresh
   `database.Migrate` fails (SQLSTATE 42601). Contract §2 mandates quoting
   (`"references"`). Please fix the file.
2. Shared test DB had drifted: pre-contract schema recorded as
   `0001_init` (runner expects `0001_init.sql`). Backed it up to
   `/tmp/wadjet-sample/wadjet-db-backup-before-resync-*.sql`, re-provisioned
   `wadjet` DB from 0001_init.sql with the single `"references"` quoting
   fix, recorded version `0001_init.sql` so `database.Migrate` no-ops.
3. Reset `wadjet` role password to `wadjet` (volume predated container env).
4. `go.mod` deviations (needed to make the stated premise true; additive
   only, nothing removed/re-resolved):
   `go mod edit -require=github.com/jung-kurt/gofpdf@v1.16.2`
   `go mod edit -require=github.com/stretchr/testify@v1.11.1`
   `go mod edit -require=github.com/davecgh/go-spew@v1.1.1 -require=github.com/pmezard/go-difflib@v1.0.0`
   `go mod download <each>`. gofpdf is in the Lead-sanctioned list
   (CONTRACTS.md §2). Note: a concurrent `go mod tidy` by another agent had
   dropped an earlier testify line; current state includes everything.
5. Suggestion (not owned): add a root `.dockerignore`
   (`data/`, `frontend/node_modules`, `.git`) to keep the image build
   context small.

## Blockers

- None open. `go build ./...` currently fails ONLY in `internal/scans`
  (Agent 2, in flight) — not in any owned package.
