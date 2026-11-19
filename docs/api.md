# WADJET REST API

Base URL: `/api/v1` · Authentication: `Authorization: Bearer <token>` or
`wadjet_session` cookie · Content type: `application/json`

Machine-readable spec: [`openapi.yaml`](../openapi.yaml).

## Conventions

| Aspect | Rule |
|---|---|
| Success | entity object, or list envelope `{"items": [...], "total": n}` |
| Errors | `{"error": {"message": "human readable"}}` with correct status |
| Status codes | 400 validation · 401 unauthenticated · 404 missing/foreign-project · 409 conflict · 422 semantic · 429 rate limit |
| UUIDs | all identifiers are UUIDv4 |
| Pagination | `?limit=&offset=` on collections |

## Authentication

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/login` | `{email, password}` → `{user, token}`; sets cookie |
| POST | `/auth/register` | account creation (password ≥ 10 chars). Open only while no users exist (bootstrap); afterwards requires an authenticated **admin** caller (403 otherwise) |
| POST | `/auth/logout` | revokes session token |
| GET | `/auth/me` | current user |

Example:

```bash
TOKEN=$(curl -s -X POST $BASE/auth/login -d '{"email":"admin@wadjet.local","password":"***"}' | jq -r .token)
```

## Projects

| Method | Path | Notes |
|---|---|---|
| GET | `/projects?q=&status=&sort=&order=&limit=&offset=` | search/filter |
| POST | `/projects` | `{name, description, tags[], settings}` |
| GET/PUT/DELETE | `/projects/{id}` | DELETE requires `?force=true` + archived (retention rule) |
| POST | `/projects/{id}/archive` | status → archived |
| POST | `/projects/{id}/clone` | `{name, description?, copy?:{settings,targets,scanner_configs,profiles,tags,report_prefs}}` — fresh IDs, no history |

## Targets (the authorization allowlist)

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/projects/{id}/targets` | `{target, target_type, excluded, note}` |
| PUT/DELETE | `/targets/{id}` | |

**Every scan enforces this allowlist twice**: at creation (400 `target not
authorized`) and again per-target at execution time (denied targets recorded
in `scan_session_targets` with status `denied`; siblings continue).

## Assets & observations

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/projects/{id}/assets` | manual registration; 409 on identity conflict |
| GET/PUT/DELETE | `/assets/{id}` | identity immutable after creation |
| GET | `/assets/{id}/history` | append-only `asset_observations` (newest first) |
| GET | `/projects/{id}/observations` | recent observations across assets |

Scanner-discovered assets arrive automatically during ingest with
`discovery_source="scanner"`.

## Scanner registry

| Method | Path | Notes |
|---|---|---|
| GET | `/scanners` | registry entries incl. parsed manifest |
| GET | `/scanners/{id}` | by id or name |
| PUT | `/scanners/{id}/enabled` | enable/disable (admin) |
| POST | `/scanners/{id}/check` | re-run `executable --version` health probe |

## Scan profiles

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/projects/{id}/profiles` | `{name, description, target_selection[], excluded_targets[], timeout_seconds, report_prefs, scanners:[{scanner_id, config, sort_order}]}` |
| GET/PUT/DELETE | `/profiles/{id}` | PUT replaces scanner bindings atomically |

## Scan sessions

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/projects/{id}/scans` | POST: `{name, targets[], scanner_configs:[{scanner, config}]}` **or** `{name, targets[], profile_id}` |
| GET | `/scans/{id}` | session + per-scanner executions |
| POST | `/scans/{id}/start` | queue + async execute (draft/queued/cancelled only) |
| POST | `/scans/{id}/cancel` | cooperative cancellation |

Status lifecycle: `draft → queued → running → completed |
completed_with_errors | failed | cancelled`.

### Real-time progress (SSE)

| Method | Path | Notes |
|---|---|---|
| GET | `/events` | global stream (`event:` = topic, `data:` = JSON). Authenticated |
| GET | `/scans/{id}/events` | session-filtered stream. Authenticated |

Event kinds: `scan.status` `{session_id, status, error?}`,
`scan.progress` `{session_id, assets_processed, findings_created,
findings_updated}`, `execution.status` `{session_id, execution_id, scanner,
status, assets_observed, findings_found, error?}`,
`report.status` `{report_id, project_id, status, file_size}`.

## Findings

| Method | Path | Notes |
|---|---|---|
| GET | `/projects/{id}/findings?severity=&status=&scanner=&asset_id=&q=&sort=&limit=&offset=` | |
| POST | `/projects/{id}/findings` | manual finding creation |
| GET | `/findings/{id}` | full detail incl. evidence |
| GET | `/findings/{id}/history` | status transitions + observations |
| PUT | `/findings/{id}/status` | `{status: open|confirmed|remediated|accepted_risk|false_positive, note}` — audited, history-appended |

Dedup key: `UNIQUE(project_id, asset_id, fingerprint)`; fingerprint =
sha256(canonical {scanner, normalized title, port, protocol})[:32].
Re-detection never overwrites status except reopening `remediated → open` with
an audit note.

## Reports

| Method | Path | Notes |
|---|---|---|
| POST | `/projects/{id}/reports/scan` | `{session_id}` → async scan assessment PDF |
| POST | `/projects/{id}/reports/findings` | `{consolidated: bool, severity[]?, asset_id?, session_id?}` → single PDF or ZIP of per-finding PDFs + `manifest.csv` |
| POST | `/findings/{id}/report` | standalone advisory PDF |
| GET | `/reports?project_id=&type=` / `/reports/{id}` | history |
| GET | `/reports/{id}/download` | completed files served from disk without regeneration |

## Audit

| Method | Path | Notes |
|---|---|---|
| GET | `/audit?limit=` | append-only action trail (authenticated, **admin** only) |

## Health

`GET /healthz` (unauthenticated): `{"status":"ok","service":"wadjet"}`.
