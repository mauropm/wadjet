# WADJET Scanner Development Guide

This guide explains how to integrate a new security tool into WADJET's
scanner engine. The engine is built from four packages:

| Package | Role |
|---|---|
| `internal/scanners/manifest` | YAML manifest loading + validation (the single source of truth for what a scanner may do) |
| `internal/scanners/registry` | Loads manifests, persists them to the `scanners` table, instantiates adapters, tracks availability |
| `internal/scanners/adapters/command` | Generic, secure external-process adapter |
| `internal/scanners/<tool>` | Tool-specific adapter (argv building, output parsing, classification) |

The shared contracts — `Scanner`, `ScanRequest`, `ScanResult`,
`AssetObservationData`, `FindingResult`, `ResultSink` — live in
`internal/scanners/scanner.go` and are owned by the Engineering Lead. Never
edit them; propose changes via your progress file.

---

## 1. Two adapter kinds

### `adapter: command` — external binaries

The tool runs as a child process via `exec.CommandContext` with an explicit
`[]string` argv. Two flavors:

1. **Purely declarative** (e.g. `configs/scanners/nuclei.yaml`): the
   manifest supplies a fixed `arguments` template with `{{target}}` and
   `{{workdir}}` placeholders. Each placeholder expands to *whole argv
   elements* — user input is never word-split or interpolated into a shell
   string. `output.parser: none` archives raw stdout only.
2. **Structured adapter** (e.g. nmap): a Go package registered in
   `registry.builtinFactories` under the manifest's `output.parser` key.
   It supplies an allowlist-driven argv builder and a real parser via
   `command.NewWithArgBuilder(manifest, parser, argBuilder)`.

### `adapter: native` — in-process Go scanners

No executable at all. Implement `scanners.Scanner` directly and register a
factory for your `output.parser` key. See
`internal/scanners/nativeprobe` (TCP connect probe) for the reference.

---

## 2. Manifest guide

Manifests live in the configured scanner directory (`WADJET_SCANNER_DIR`,
shipped examples in `configs/scanners/`). Example:

```yaml
name: nmap                     # slug: ^[a-z0-9][a-z0-9._-]{0,63}$
display_name: Nmap
description: Network discovery and vulnerability assessment
version: auto                  # informational; overwritten by --version probe
executable: nmap               # bare name or path; NO shell metacharacters ever
adapter: command               # command | native
enabled: true                  # initial value; DB state wins after first load

asset_types: [ip, ipv6, hostname, domain]   # subset of ip,ipv6,hostname,domain,cidr,url
capabilities:                              # subset of the Capability constants
  - host_discovery
  - port_discovery
  - service_detection
  - os_detection
  - vulnerability_detection

output:
  format: xml                  # xml | json | text | csv | none
  parser: nmap_xml             # registry factory key; "none" archives raw output
  extension: xml               # raw output file extension

configuration:
  timeout: 1800                # per-execution timeout, seconds, > 0
  acceptable_exit_codes: [2]   # extra exit codes meaning "success"
  env_allowlist: [NMAPDIR]     # extra env vars forwarded to the child
  options:                     # user-settable knobs (validated!)
    - {id: timing, label: Timing, type: select, default: normal,
       options: [slow, normal, fast]}
    - {id: ports, label: Ports, type: string}
    - {id: max_parallelism, label: Max Parallelism, type: number, min: 1, max: 128}
    - {id: scripts, label: NSE Scripts, type: multiselect, options: [safe, vuln]}
    - {id: service_detection, label: Service Detection, type: boolean, default: true}

arguments:                     # command adapter only (declarative flavor)
  - -silent
  - -target
  - "{{target}}"
```

The loader (`manifest.LoadDir`) rejects, at load time:

- missing `name`/`display_name`; malformed slugs;
- `adapter` outside `{command, native}`; missing `executable` for command;
- **any shell metacharacter, space, quote, glob or control character in
  `executable`** (`; | & $ \` ( ) < > ' " \` etc.);
- option ids that are duplicated or malformed; option types outside
  `{boolean,string,number,multiselect,select}`;
- `select`/`multiselect` options without choices, or defaults outside the
  choice set; number ranges with `min > max`;
- capabilities or asset types outside the allowlists;
- `output.format` outside `{xml,json,text,csv,none}` or a missing parser
  key;
- timeouts ≤ 0, exit codes outside 1–255;
- `arguments` templates containing placeholders other than `{{target}}`
  and `{{workdir}}`;
- duplicate scanner names across files, and unknown YAML keys.

Manifests load once at startup and UPSERT into the `scanners` table with
the full manifest as JSONB. Reloads never re-enable a scanner you disabled
via the API.

---

## 3. Security constraints (binding)

1. **No shell. Ever.** Child processes start only through
   `exec.CommandContext` with discrete argv elements. If you find yourself
   wanting `sh -c`, the answer is a native scanner or a parser change.
2. **Allowlist-driven argv.** User configuration values reach argv only via
   *fixed, code-owned fragments*. For every option that influences argv:
   - `select`/`multiselect`: values must be members of the manifest's
     static option set (checked twice: schema + adapter).
   - `string` values must pass a strict per-option regex (e.g. nmap ports
     `^[0-9]+(-[0-9]+)?(,…)*$` with 1–65535 validation; NSE script ids
     against a curated known set, never a free-form name).
   - Values failing validation **abort the execution**; they are never
     "sanitized" and passed.
   - Reject values starting with `-` so they cannot masquerade as flags,
     and reject targets starting with `-` likewise.
3. **The executable path comes only from a validated manifest** — never
   from request or scanner configuration input.
4. **Minimal child environment.** Children receive base vars (`PATH`,
   `HOME`, …) plus the manifest's explicit `env_allowlist`. Secrets in
   `WADJET_*` never leak to tools.
5. **Scanner output is untrusted input.** Parsers must tolerate malformed,
   truncated, hostile XML/JSON without panicking; malformed attributes
   become `ScanResult.Errors`, never fatal parse errors. Raw output is
   stored on disk and never rendered directly.
6. **Never fabricate CVEs or CVSS.** Populate `CVEs` only by extracting
   literal `CVE-YYYY-NNNN` text from scanner output; leave `CVSSScore` nil
   unless trusted intelligence supplies it.
7. **Findings only from genuine issues.** Classification is a curated table
   (script id + output patterns → title/severity/remediation). Anything
   that does not match stays an INFO observation in
   `AssetObservationData.Extra["scripts"]`. Banner/inventory scripts
   (`http-title`, `http-server-header`, …) are observations, never
   findings.
8. **Privilege degradation.** Options that need root (e.g. `-O`) are
   dropped with a logged notice when the process is unprivileged, never
   executed via sudo.

---

## 4. Adding a structured command adapter (walkthrough)

1. Write `configs/scanners/<tool>.yaml` with a unique `output.parser` key,
   e.g. `parser: mytool_xml`.
2. Create `internal/scanners/<tool>/` with:
   - `args.go` — `BuildArgs(m *manifest.Manifest, req scanners.ScanRequest)
     ([]string, error)`: fixed fragments + strictly validated values only;
   - `parser.go` — `Parse(raw []byte) (*scanners.ScanResult, error)`;
   - `classify.go` (optional) — curated evidence→finding table;
   - `<tool>.go` — `func New(m *manifest.Manifest) (*X, error)` wiring
     `command.NewWithArgBuilder(m, command.ParserFunc(Parse), buildFn)`.
3. Register the factory in `internal/scanners/registry/registry.go`:

   ```go
   var builtinFactories = map[string]Factory{
       ...
       "mytool_xml": func(m *manifest.Manifest) (scanners.Scanner, error) {
           return mytool.New(m)
       },
   }
   ```

4. Table-driven tests: arg builder accept/reject matrix, injection
   attempts (`; rm -rf`, spaces, `--evil`), parser fixtures under
   `testdata/` committed to the repo, and LookPath-guarded integration
   tests against the real binary.

## 5. Adding a native scanner

1. Implement `scanners.Scanner` (see `nativeprobe`). Respect `ctx` for
   cancellation and the request timeout; produce `AssetObservationData`
   and leave `Findings` empty unless you have genuine evidence rules.
2. Declare the option schema in code (`manifest.OptionSpec` list) so
   `ValidateConfig` rejects unknown keys, and mirror it in the YAML
   manifest with `adapter: native`, `output: {format: none, parser: my_probe}`.
3. Register the factory as above.

---

## 6. Execution flow & orchestration guarantees

The orchestrator (`internal/orchestration`) drives every session:

```
queued → running → (completed | completed_with_errors | cancelled | failed)
```

- Every raw target is authorized through `TargetAuthorizer` before use.
  DENY records the target row as `denied` and continues with the rest.
- Targets are normalized: CIDRs expand (capped at 1024 hosts — larger
  prefixes are rejected), hostnames resolve with a 5s bound and resolved
  IPs are recorded, malformed inputs are rejected per target.
- One `scanner_executions` row per scanner; executions run under a
  concurrency semaphore with a per-execution timeout context. **A failing
  execution never aborts its siblings**; the session becomes
  `completed_with_errors` and already-collected results are always kept.
- Raw output is written to `WADJET_RAW_OUTPUT_DIR/<session>/<execution>.<ext>`
  before ingestion; ingest failures mark the execution failed but preserve
  the raw file.
- Cancellation: `orchestrator.Cancel(sessionID)` cancels all live
  executions of that session.

## 7. SSE event contract

Published on `events.Bus` with topic `scan` (see CONTRACTS.md §4):

| Kind | Payload |
|---|---|
| `scan.status` | `{session_id, status, error?}` |
| `scan.progress` | `{session_id, assets_processed, findings_created, findings_updated}` |
| `execution.status` | `{session_id, execution_id, scanner, status, assets_observed, findings_found, error?}` |

`GET /api/v1/scans/{id}/events` relays these filtered to one session with
a 25s heartbeat; `GET /api/v1/events` (Lead-owned) fans out everything.

## 8. Availability checks

`registry.CheckAvailability` runs `executable --version` via
`exec.CommandContext` bounded at 10s and persists `version`,
`status ∈ {available, missing}` (or `disabled`/`unknown` appropriately) and
`last_checked_at`. Only `registered + enabled + available` scanners execute.
Trigger a re-check via `POST /api/v1/scanners/{id}/check`.
