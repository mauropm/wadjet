# Agent 4A — Frontend / UX / Product Design — Progress

Owner: `frontend/` (Vite + React 18 + TS + Tailwind v3). Reports backend (`internal/reports/`) is owned by
the Agent 4 backend track; this file tracks the UI only.

## Status: ✅ COMPLETE — `npm run build` passes (tsc strict), 15/15 vitest tests green, dev server smoke-tested

## Completed

### Infrastructure
- `package.json` (tight real deps: react 18, react-router-dom 6, lucide-react, cva, clsx,
  tailwind-merge, @fontsource/inter; dev: vite 5, tailwind 3.4, typescript 5.6 strict, vitest 2).
- `vite.config.ts` (proxy `/api` → `http://localhost:8080`, `@/` alias), `tailwind.config.js`
  (brand palette tokens: base/panel/raised/line/ink/mute/accent/gold/sev-*, keyframes,
  150ms transitions), `tsconfig.json` (strict, noUnusedLocals), `postcss.config.js`,
  `index.html` (dark class default), `public/wadjet.svg` favicon, `.gitignore`.
- `src/lib/types.ts` — exact mirror of `internal/models/models.go` JSON tags + request
  payload types + scanner manifest option types.

### Core libs
- `src/api/client.ts` — typed fetch wrapper: base `/api/v1`, Bearer from
  `localStorage('wadjet_token')`, 401 → clear token + redirect `/login`, `{error:{message}}`
  parsing, `ApiError`, `unwrap()` lenient list helper, blob download for reports.
  All endpoint groups: auth/projects/targets/assets/profiles/scans/scanners/findings/reports/audit.
- `src/api/sse.ts` — EventSource on `GET /api/v1/events`, exponential backoff + jitter
  (500ms→30s, reset on open), listens on full topic names AND prefix events ("scan", "report")
  and normalizes `data.kind` → covers both readings of the §4 wire contract.
- `src/lib/severity.ts` — central severity/status rendering: colors (#EF4444/#F97316/#EAB308/
  #3B82F6/#64748B), emoji (🔴🟠🟡🔵⚪), labels, weights; finding/scan/exec/report status maps;
  asset-type & discovery labels; scanner status dots.
- `src/lib/auth.tsx` (AuthContext: login/register/logout//me bootstrap),
  `src/lib/use-api.ts` (data hook), `src/lib/use-report.ts` (generate→poll→download flow),
  `src/lib/utils.ts` (cn, dates, durations, bytes, tags, qs).

### Design system (`src/components/ui/`)
button (+variants), input/textarea/select/label/Field, card, badge/chip, table, tabs,
dialog (portal, Esc, focus mgmt), sheet (drawer), toast (provider+hooks), skeleton/rows/cards,
progress (determinate+indeterminate), dropdown-menu, switch, separator.
All cva-based, focus-visible emerald rings, aria roles.
(Label/Textarea/Select live in `input.tsx`, Separator in `switch.tsx` — grouped exports,
component names as specced.)

### Brand
- `src/components/logo.tsx` — `WadjetEye`: abstract stroke-built eye (teardrop outline,
  iris, pupil, tail strokes, brow) — login (large) + sidebar (small) + Wordmark lockup.
- `src/components/app-shell.tsx` — fixed sidebar ≥lg, mobile top bar + sheet nav, user footer.

### Key deliverable
- `src/components/scanner-config-form.tsx` — dynamic form engine auto-rendering from
  `manifest.configuration.options[]`: boolean→toggle, multiselect→chip multi-select,
  select→dropdown, number→input, string→input; lenient manifest parse (object or JSON string);
  `defaultConfig()`; `ConfigSchemaView` read-only renderer for /scanners.

### Pages (all data via typed API client — zero mock data)
- `/login` — big eye, wordmark, tagline 👁️, show/hide password, register mode, error states.
- `/` Overview — real-data severity snapshot (aggregate client-side over recent projects'
  findings), recent projects, recent scans, quick actions. No fake widgets.
- `/projects` — search, cards, status/tags/last activity; New Project dialog; Clone dialog
  with copy-checklist (settings/targets/scanner configs/profiles/tags/report prefs);
  archive; delete.
- `/projects/:id` tabs: Overview (scope chips incl. excluded, quick stats, recent sessions) ·
  Assets (table + manual-add form + row → `/assets/:id`) · Scan Profiles (card per enabled
  scanner, dynamic config, target chips, timeout) · Scan Sessions (live-colored status,
  start/cancel, report download) · Findings (severity chips/status/scanner/q filters,
  sort severity⇄date, pagination, bulk selection → status dialog with note) ·
  Reports (history + 3 generators: scan w/ session picker, consolidated, ZIP) ·
  Settings (edit, target rows CRUD incl. excluded, danger zone w/ typed confirm).
- `/assets/:id` — identity card, latest ports/services table (rendered from raw observation
  JSON), observation history timeline, asset findings.
- `/scans/:id` — LIVE via SSE scan.status/scan.progress/execution.status with animated
  progress + "live" pulse; per-execution cards (status, raw-output path, errors, log);
  Start (draft)/Cancel (running)/Download report; 10s fallback poll while running.
- `/findings/:id` — severity banner + CVSS dial, asset link, port/service/protocol, CVE chips
  → NVD (rel=noopener), description/technical/evidence as escaped monospace blocks (untrusted —
  never innerHTML), remediation, references (external, rel=noopener), detection timeline
  (`/findings/{id}/observations` w/ 404 fallback), status history, status control + note,
  Download PDF (POST `/findings/{id}/report` → poll → download).
- `/projects/:id/scans/new` — 5-step wizard: Targets (checkboxes + ad-hoc + exclusions shown)
  → Profile/custom → Scanners + dynamic config → Review → Launch 🚀 (create + start → live page).
- `/scanners` — status dot/version/capabilities/asset-types, enable switch (PUT
  `/scanners/{id}/enabled` {enabled}), expandable docs + config schema + raw manifest.
- `/settings` — user card, sign out, audit log viewer (graceful 404 empty state).
- `*` 404 with personality.

### Tests (vitest, node env, react-dom/server rendering)
- `src/lib/severity.test.ts` — 9 tests: colors/emoji per brand spec, case-insensitivity,
  weight ordering, unknown-value degradation, status-map coverage of models.go enums.
- `src/components/chips.test.tsx` — 6 tests: SeverityChip emoji+label+color class, CVSS
  rounding, StatusChip live animation for running, Button loading/disabled.

## Build output
- `npm run build` → tsc --noEmit clean (strict) + vite build ✓ (339 kB JS / 98.7 kB gzip,
  43 kB CSS / 8.6 kB gzip, self-hosted Inter fonts emitted).
- `npm test` → 15 passed.
- Dev server smoke: `/` 200, `/src/main.tsx` transforms, `/wadjet.svg` 200. Killed after test.

## Contract notes / mismatches (for Lead + owning agents)

1. **`POST /projects/{id}/scans` custom body is unspecified** (models.go has no request struct).
   UI sends `{name, profile_id?, targets?, scanners:[{scanner, config}]}`. Because Lead's
   `DecodeJSON` uses `DisallowUnknownFields()`, Agent 2's handler must accept exactly these
   fields (single integration point; adjust in `api/client.ts → projectsApi.createScan`).
2. **`POST /projects/{id}/clone` option names unspecified** — UI sends `{name?, copy_settings,
   copy_targets, copy_scanner_configs, copy_profiles, copy_tags, copy_report_prefs}`.
3. **`POST /projects/{id}/reports/findings`** — UI sends `{type: "findings_consolidated" |
   "findings_zip"}` to disambiguate the two contract report types on the one endpoint.
4. **`GET /api/v1/audit`** not in CONTRACTS.md — UI calls it and renders a friendly empty
   state on 404 (settings page).
5. **`GET /findings/{id}/observations`** not in contract (FindingObservation model exists but
   no listed route) — UI tries it, degrades to first/last-detected copy on 404.
6. **SSE event-name ambiguity** (§4 table "topic scan kind scan.status" vs "`event:` = topic") —
   handled both ways client-side (prefix + kind normalization).
7. Findings list filters (`?severity=&status=&scanner=&q=`) are sent but also applied
   client-side, so filtering/sorting works even if Agent 3 ignores the params.
8. Login response `{user, token}` consumed as implemented in `auth_handlers.go`; cookie
   `wadjet_session` (set by server at login) authenticates EventSource since EventSource
   cannot send Authorization headers.

## Next actions (handoff)
- End-to-end test against running Go server once Agents 2–4 backend land; verify scan-create
  body (note 1) against the real handler first.
