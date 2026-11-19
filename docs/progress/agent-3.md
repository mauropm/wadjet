# Agent 3 — Asset Management / Findings / Database Intelligence

Status: **in progress** (started 2026-11-18)

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

## Notes / contract observations

* `go.mod` does **not** contain `stretchr/testify` or `yaml.v3` (only chi, uuid, pgx,
  x/crypto, x/time). `go get` is forbidden, so all tests use the standard `testing`
  package. If the Lead runs `go mod tidy` after adding gofpdf/yaml/testify, my packages
  keep working unchanged.
* `findings.Ingest` needs one transaction across asset upserts and finding upserts. To
  keep `assets.UpsertFromScan` usable standalone *and* transaction-scoped, `assets` also
  exports `UpsertFromScanTx(ctx, q assets.Querier, ...)` where `assets.Querier` is
  satisfied by both `*database.DB` and `pgx.Tx`. No contract change needed.

## Progress log

* [x] Read CONTRACTS.md, models.go, scanner.go, 0001_init.sql, audit.go, respond.go
* [ ] internal/projects
* [ ] internal/targets (+ Authorize security gate)
* [ ] internal/assets
* [ ] internal/findings (ResultSink)
* [ ] internal/profiles
* [ ] gofmt / go vet / go build / go test green
