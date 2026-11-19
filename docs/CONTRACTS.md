# WADJET Integration Contracts (Agent 1 — Engineering Lead)

This document is the binding contract between all four engineering agents.
Read it fully before writing code.

## 1. Module ownership

| Path | Owner |
|---|---|
| `cmd/`, `internal/api/`, `internal/config/`, `internal/database/`, `internal/models/`, `internal/auth/`, `internal/audit/`, `migrations/` | Agent 1 (Lead) |
| `internal/scanners/` (except `scanner.go`), `internal/orchestration/`, `configs/scanners/`, `docs/scanner-development.md` | Agent 2 (Scanning) |
| `internal/projects/`, `internal/assets/`, `internal/findings/`, `internal/profiles/`, `internal/targets/` | Agent 3 (Intelligence) |
| `frontend/`, `internal/reports/`, `demo/` | Agent 4 (Experience) |

Do not create or edit files outside your ownership. `internal/scanners/scanner.go`
and `internal/models/models.go` are **shared contracts owned by the Lead** —
read them, never edit them. If a contract change is needed, note it in your
progress file instead.

## 2. Go conventions

- Service packages expose: `func NewService(db *database.DB, deps...) *Service`
  and `func (s *Service) Register(r chi.Router)` where `r` is mounted at
  `/api/v1` and **auth middleware is already applied outside** it.
- Handlers get the current user via `auth.UserFromContext(r.Context())`.
- JSON responses: entities as objects; lists as `{"items": [...], "total": n}`.
- Errors: `{"error": {"message": "..."}}` with proper HTTP status codes.
- Use the JSON helpers in `internal/api` (`WriteJSON`, `WriteList`,
  `WriteError`, `DecodeJSON`) from your handler code.
- All SQL parameterized (`$1` style) via pgx. **`references` is a reserved
  word: always quote it as `"references"` in SQL.**
- `text[]` ↔ `[]string`, `inet` ↔ `*string` (nullable, text form), `jsonb` ↔
  `json.RawMessage` via pgx.
- No new module dependencies. Available: pgx/v5, chi/v5, uuid, yaml.v3,
  gofpdf, testify, x/crypto, x/time. If truly blocked, write
  `DEPS-<yourname>.txt` explaining why.
- `go build ./...` and `go vet ./...` must pass for your packages. Run
  `gofmt -w` on your files.

## 3. Scanner contracts (Agent 2 provides, Agent 3 implements sink)

Defined in `internal/scanners/scanner.go`: `Scanner`, `ScanRequest`,
`ScanResult`, `AssetObservationData`, `FindingResult`, `ScannerConfig`,
`Target`, `ResultSink`.

- Agent 2's orchestrator calls `ResultSink.Ingest(ctx, sessionID, executionID,
  scannerName, result)` after each successful execution.
- Agent 3 implements `ResultSink` in `internal/findings` as
  `func (s *Service) Ingest(...)` — upserting assets, appending
  `asset_observations`, deduplicating findings via fingerprint, appending
  `finding_observations`, updating counters.
- Raw scanner output is stored on disk under `WADJET_RAW_OUTPUT_DIR` by the
  orchestrator, path recorded in `scanner_executions.raw_output_path`.

## 4. REST API surface (v1)

Auth (Lead, done): `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`,
`GET /api/v1/auth/me`, `POST /api/v1/auth/register`.

Projects & targets & profiles (Agent 3):
```
GET/POST /projects                    GET/PUT/DELETE /projects/{id}
POST /projects/{id}/clone             POST /projects/{id}/archive
GET/POST /projects/{id}/targets       PUT/DELETE /targets/{id}
GET/POST /projects/{id}/profiles      GET/PUT/DELETE /profiles/{id}
GET/POST /projects/{id}/assets        GET/PUT/DELETE /assets/{id}
GET /assets/{id}/history              GET /projects/{id}/observations
GET/POST /projects/{id}/findings      GET /findings/{id}
PUT /findings/{id}/status             GET /findings/{id}/history
```

Scanners & scans (Agent 2):
```
GET /scanners                         GET /scanners/{id}
PUT /scanners/{id}/enabled
POST /projects/{id}/scans             GET /projects/{id}/scans
GET /scans/{id}                       POST /scans/{id}/start
POST /scans/{id}/cancel               GET /scans/{id}/events   (SSE)
```

Reports (Agent 4):
```
POST /projects/{id}/reports/scan      POST /projects/{id}/reports/findings
POST /findings/{id}/report            GET /reports              GET /reports/{id}
GET /reports/{id}/download
```

SSE events (Agent 2 defines payload, Lead's bus relays): topics `scan.status`,
`scan.progress`, `execution.status`.

### SSE wire contract (binding)

Clients subscribe `GET /api/v1/events` (EventSource, cookie or Bearer).
`event:` field = topic; `data:` = JSON payload:

```
topic scan  kind scan.status    {session_id, status, error?}
topic scan  kind scan.progress  {session_id, assets_processed, findings_created, findings_updated}
topic scan  kind execution.status {session_id, execution_id, scanner, status,
                                   assets_observed, findings_found, error?}
topic report kind report.status {report_id, project_id, status, file_size}
```

Frontend reconnects with exponential backoff; server keeps 25s heartbeat.

## 5. Auth & middleware

`auth.Service` in `internal/auth`. Token arrives as `Authorization: Bearer <t>`
or `wadjet_session` cookie. Lead provides middleware in `internal/api`.

## 6. Definition of done per agent

- Packages compile (`go build ./...`), `go vet` clean, unit tests for critical
  logic (fingerprints, cloning, manifest validation, PDF generation).
- Progress report maintained at `docs/progress/agent-<n>.md` (created at start,
  updated continuously: completed, current, blockers, interfaces).
- No placeholders, no mock data, no fake scanner execution.
