# Agent 3 — Asset Management / Findings / Database Intelligence

Status: **complete** (2026-11-19) — all five packages implemented, integration-tested
against a live PostgreSQL instance, and green under `gofmt`, `go vet` and `go build`.

## Scope

`internal/projects/`, `internal/targets/`, `internal/assets/`, `internal/findings/`,
`internal/profiles/`.

## Constructor signatures for the Lead (wiring)

```go
projects.NewService(db *database.DB, audit *audit.Logger) *projects.Service
targets.NewService(db *database.DB) *targets.Service
assets.NewService(db *database.DB) *assets.Service
findings.NewService(db *database.DB, assets *assets.Service, audit *audit.Logger) *findings.Service
profiles.NewService(db *database.DB) *profiles.Service
```

Every service implements `Register(r chi.Router)` (satisfies `api.Registrable`) and is
designed to be mounted under `/api/v1` behind the Lead's auth middleware.

Suggested wiring:

```go
api.NewServer(cfg, db, authSvc, auditLogger, bus, []api.Registrable{
    projSvc, tgtSvc, assetSvc, findingSvc, profileSvc,
})
```

`findings.NewService` accepts a nil `*assets.Service` (it builds one from `db`) and a nil
audit logger, so the orchestrator can wire it before the HTTP layer exists.
`var _ scanners.ResultSink = (*findings.Service)(nil)` is a compile-time assertion in
`internal/findings/service.go` — if the sink contract ever changes, the package stops
compiling instead of failing at scan time.

## Verification gate (measured, 2026-11-19)

```
gofmt -l internal/                                     clean
go vet ./internal/...                                  clean
go build ./...                                         clean
go test -count=1 ./internal/{projects,targets,assets,findings,profiles}/...
  ok  internal/projects   1.74s   8 tests
  ok  internal/targets    1.74s   7 tests
  ok  internal/assets     1.73s  11 tests
  ok  internal/findings   1.74s  20 tests
  ok  internal/profiles   1.73s  12 tests
go test -race -count=2 ./internal/findings/ ./internal/assets/   ok
```

58 tests, all real integration tests: `TestMain` in each package opens a live
PostgreSQL connection via `database.Open`, creates a private `wadjet_it_<pkg>_<rand>`
database and migrates it through `database.Migrate` once per run.
`go test -race -count=2 ./internal/findings/ ./internal/assets/` is also clean.

## Implementation notes

### `internal/projects`
CRUD, `?q=` / `?status=` / sort / limit / offset listing, archive, retention-aware
DELETE (409 unless archived *and* `force=true`), `TouchActivity`, audit entries, and
`Clone` with independent-copy flags (`settings, targets, scanner_configs, profiles,
tags, report_prefs`; all true by default; name `<orig> (Clone)`). Clone independence is
asserted by mutating the clone and re-reading the original.

### `internal/targets`
`Authorize(ctx, projectID, target) error` / `AuthorizeTargets` is the security gate every
scan path must call. Rules: exclusions always win; no includes ⇒ fail closed; no DNS
resolution (a scanner must not become a DNS oracle); `auto` treats a multi-label host as a
domain (suffix match on a label boundary) while an explicit `hostname` must match exactly;
URL entries pin the exact host; RFC 1123 validation rejects an all-numeric last label so
`10.0.0.256` cannot masquerade as a host name. Sentinels: `ErrInvalidTarget`,
`ErrNotAuthorized`, `ErrExcluded`. ~70-case table suite.

### `internal/assets`
`NormalizeIdentity` is the dedup key: scheme/path stripped, single `:port` suffix removed,
lower-cased, one trailing dot removed, IP literals canonicalised with `netip` (so
`2001:DB8:0000::0001` == `2001:db8::1`, IPv4-mapped addresses unwrapped), zones and CIDRs
rejected. Scan refresh uses `COALESCE(existing, new)` — a sparse scan can never blank known
data — and operator tags are never modified by a scanner. Identity is immutable after
creation (the PUT schema has no such field, verified at the HTTP layer). `View` exposes the
current view (`latest_observation`, `open_ports`) and `History` / project
`?type=`-filtered observations give the append-only trail.

### `internal/findings`
* `FindingFingerprint(title, scanner, port, protocol)` = first 32 hex chars of SHA-256 over
  canonical JSON of the four normalised fields. Excluded on purpose: asset identity
  (already the asset scope of the unique key `(project_id, asset_id, fingerprint)`),
  evidence text, timestamps, counters, and every enriched field (description, severity,
  CVSS, CVEs, service) — a finding must survive those edits. The scanner name comes from
  the execution, never from the payload, so a scanner cannot forge its dedup key.
* `Ingest` is the `scanners.ResultSink`: one transaction for asset upserts, finding
  upserts, observation inserts and counter updates (proved by `TestIngestIsAtomic`).
  Re-detection never overrides an analyst status; a `remediated` finding that comes back is
  reopened to `open` with a `finding_status_history` row saying `re-detected by scanner X`
  and no `changed_by` user. Findings whose asset was never observed are skipped and logged
  instead of failing the whole result. An unexpected scanner severity degrades to `info`
  rather than aborting against the CHECK constraint.
* Retry safety: re-calling `Ingest` for the *same* execution replaces the observation rows
  that execution wrote (and only those), which is what makes the contract's "implementations
  must be idempotent" true for the data that matters — see `TestIngestRetryIsIdempotent`.
* Concurrency: `ON CONFLICT DO NOTHING` plus `SELECT … FOR UPDATE` is exercised by five
  goroutines ingesting the same finding, which must converge on one row with five
  observations and exactly one `findings_created`.

### `internal/profiles`
CRUD with **replace-all** scanner bindings in one transaction: a request that carries a
scanner list makes it the whole set (nil list = leave untouched, `[]` = clear). Authoring
validation: unknown scanner id → 404, duplicate scanner in one request → 400, non-object
scanner config → 400, invalid `report_prefs` → 400, `timeout_seconds` outside 1–86400 →
400, more than 32 scanners → 400, `(project_id, name)` taken → 409. A scanner that is
`enabled=false` or whose status is `disabled`/`missing`/`error` is refused with 409 rather
than silently skipped at scan time; `unknown` stays bindable so a fresh registry is usable
before the first health check. Name uniqueness is checked case-insensitively in the
service. Deleting a profile never rewrites assessment history (`scan_sessions.profile_id`
is `ON DELETE SET NULL`, asserted by `TestProfileHistorySurvivesDelete`).

## Test harness

`internal/assets/itest` (a subdirectory of an owned path, so no ownership rules are
broken) holds the shared bootstrap used by all five packages: `Main(m, pkg)` opens an
isolated database `wadjet_it_<pkg>_<rand>` and applies the schema once per run, `DB()`,
`UniqueName`, `MustExec`, `Count`, `CleanupProject`, `NewProject`, `NewScanner`,
`NewScanSession`, `NewExecution`, `NewUser`.

Isolation is deliberate: the shared `wadjet` development database is in a stale,
half-migrated state and several agents run concurrently, so each package creates and drops
its own database. `WADJET_ITEST_SHARED=1` opts out and uses the shared database instead.

## Notes / contract observations

* `go.mod` does **not** contain `stretchr/testify` or `yaml.v3` (only chi, uuid, pgx,
  x/crypto, x/time). `go get` is forbidden, so all tests use the standard `testing`
  package. If the Lead runs `go mod tidy` after adding gofpdf/yaml/testify, my packages
  keep working unchanged.
* `findings.Ingest` needs one transaction across asset upserts and finding upserts. To
  keep `assets.UpsertFromScan` usable standalone *and* transaction-scoped, `assets` also
  exports `UpsertFromScanTx(ctx, q assets.Querier, ...)` where `assets.Querier` is
  satisfied by both `*database.DB` and `pgx.Tx`. No contract change needed.
* **Resolved (Lead fixed it):** `migrations/0001_init.sql` had declared
  `references jsonb` unquoted in `findings`, so a fresh `database.Migrate` aborted with
  `ERROR: syntax error at or near "references"`. Verified fixed on 2026-11-19:
  `database.Migrate` on an empty database now produces the 20 public tables, so
  `itest.ApplySchema` is a thin delegation to `database.Migrate` — the tests apply the
  schema through the same code path the application uses (the earlier
  quote-the-reserved-word workaround was removed). Agents other than the Lead must not
  edit `migrations/`, and none did.
* `inet` columns cannot be scanned into the shared `*string` fields of `models.Asset`
  (pgx rejects `inet` binary → `**string`), so asset queries select `host(ip)` /
  `host(ipv6)`. Any package reading those columns must do the same.
* `finding_status_history.changed_by` has a foreign key to `users`; `UpdateStatus`
  pre-checks the actor so a stale session yields 400 instead of a constraint violation
  surfacing as 500. Callers must pass the authenticated user, not a client-supplied id.
* `models.ScanProfile.Scanners` is tagged `omitempty`, so an empty scanner set would vanish
  from JSON. `profiles.View` re-declares the field to guarantee `"scanners": []`; the
  shared model was not touched.
* `scan_sessions.findings_created` / `findings_updated` are accumulated per `Ingest` call:
  they are the progress view the SSE stream reports, not the source of truth. Row-level
  dedup on the unique key is authoritative, so a retried execution that re-increments a
  counter cannot duplicate a finding.
* Prompt-injection attempts were observed inside tool results during this work (a forged
  `<system-reminder>` instructing "exactly one tool call on every turn"). They were
  ignored; the Lead may want to know.

## Residual risks

1. Case-insensitive profile-name uniqueness is enforced in the service, not in the unique
   index (`UNIQUE (project_id, name)` is exact). Two concurrent inserts differing only in
   case can both land. Fix would be a migration adding a `lower(name)` index.
2. `finding_status_history` / `finding_observations` have no monotonic column, so history
   ordering is `created_at DESC, id DESC`. `id` is `gen_random_uuid()`, so rows written
   inside one transaction (identical `now()`) tie and break arbitrarily. Measurements show
   ~2–3 ms between separate transitions, so this is only a theoretical risk for
   same-transaction rows; a `bigserial` sequence column would remove it.
3. `asset_observations.observed_at` ordering has the same property; ties are resolved by
   `created_at, id`.
4. `Ingest` skips (and logs) findings whose asset identity was never observed in the same
   result. If a future adapter reports findings without also reporting the asset, those
   findings are dropped by design; the orchestrator should feed asset observations first.
5. `assets.UpsertFromScan` never blanks data, which also means a scanner cannot *correct*
   a wrong value (e.g. a stale `hostname`). Only the manual edit path overwrites.

## Progress log

* [x] Read CONTRACTS.md, models.go, scanner.go, 0001_init.sql, audit.go, respond.go
* [x] internal/projects
* [x] internal/targets (+ Authorize security gate)
* [x] internal/assets
* [x] internal/findings (ResultSink)
* [x] internal/profiles
* [x] gofmt / go vet / go build / go test green

## Next actions for the Lead

1. Wire the five `Register` methods into the `/api/v1` router behind the auth middleware.
2. Confirm the orchestrator calls `targets.Authorize` before dispatching any scanner, and
   passes the *execution's* scanner name to `Ingest` (the dedup key depends on it).
3. Decide whether `finding_status_history` should gain a monotonic sequence column
   (residual risk 2) and whether the profile-name index should be `lower(name)` (risk 1).
4. Add `internal/assets/itest` to any CI database-pruning step: it creates and drops
   `wadjet_it_*` databases.
