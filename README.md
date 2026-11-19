# 👁️ WADJET

**We see what your assets are hiding.**

WADJET is an open-source, self-hosted vulnerability assessment and management
platform inspired by Rapid7 InsightVM — without the enterprise bloat. Discover
infrastructure, run real security scanners, track findings across assessments,
and generate professional PDF reports.

```text
Create Project → Configure Scope → Select Scanners → Launch Assessment 🚀
      → Discover Assets → Identify Findings → Review Vulnerabilities
      → Generate Reports → Export Individual PDFs → Clone Project
```

## Features

- 📁 **Projects** — assessment scopes with authorized/excluded target allowlists, tags, and one-click **cloning** for recurring assessments.
- 🖥️ **Persistent asset inventory** — assets survive restarts and every scan appends immutable **observations** (port history across scans is never overwritten).
- 🔎 **Extensible scanner registry** — declarative YAML manifests + external command adapters + native Go adapters. Nmap ships today; Nuclei, Nikto, testssl.sh, Trivy and friends plug in without touching the core.
- 🚀 **Multi-scanner scan sessions** — select several tools per profile, execute asynchronously with cancellation, timeouts, and concurrency limits, watch live progress over **SSE**.
- 🐛 **Findings with deduplication** — normalized findings keyed by asset + fingerprint persist across sessions; every detection is preserved as an append-only **observation**; full status lifecycle (open → confirmed → remediated / accepted risk / false positive) with audit history.
- 📄 **Professional PDF reporting** — full assessment reports, standalone per-finding advisories, consolidated findings PDF, and ZIP export of every finding as its own PDF. Reports persist on disk and re-download without regeneration.
- 🔐 **Security first** — bcrypt auth, DB-backed sessions, target allowlists enforced before execution, allowlist-driven argv construction (no shell strings), untrusted-output hardening in parsers and PDFs, audit logging, rate limiting.

## Quick start

```bash
cp .env.example .env          # defaults work for local development
docker compose up -d          # PostgreSQL + WADJET (image includes nmap)
open http://localhost:8080    # API — frontend served by Vite below
```

Frontend development:

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173 (proxies /api → :8080)
```

Default credentials (bootstrap admin, override via `.env`):
`admin@wadjet.local` / `admin`

### Demonstration lab

A self-contained vulnerable lab (Juice Shop, WebGoat, nginx, SSH, TLS, noisy
services) lives in an isolated private Docker network:

```bash
docker compose -f demo/docker-compose.yml up -d
go run ./demo/seed            # creates the 🧪 Demo Lab project
```

See [demo/README.md](demo/README.md). Seeded data is always clearly marked as
demo data — findings always come from **real scanner executions**.

## Architecture

Modular monolith in Go; React + TypeScript + Tailwind frontend; PostgreSQL for
all persistence; no Redis/Kafka/queue infrastructure.

```text
        React / Vite / Tailwind (dark-first)
                     │  REST + SSE
              Go REST API (chi)
                     │
   ┌────────────┬────┴───────┬──────────────┐
   v            v            v              v
 Projects     Assets     Findings       Reports
 (clone)   (observations) (fingerprint)  (gofpdf)
                     │
              Scan Orchestrator ── SSE progress
                     │
              Scanner Registry
             ┌───────┴────────┐
        command adapter   native adapters
             │                  │
           nmap            tcp-probe (example)
             │
      YAML manifests → parsers → normalization → PostgreSQL
```

- [docs/architecture.md](docs/architecture.md) — module boundaries and data flow
- [docs/database.md](docs/database.md) — schema and ER diagram
- [docs/scanner-development.md](docs/scanner-development.md) — add a new scanner in one manifest
- [docs/CONTRACTS.md](docs/CONTRACTS.md) — internal integration contracts

## Engineering principles

1. PostgreSQL stores data — **never** business logic (no stored procedures, no triggers).
2. All SQL parameterized; transactions where correctness demands them.
3. UUID primary keys everywhere; JSONB for scanner-specific payloads.
4. Scanner output is untrusted input, end to end.
5. Everything persists across restarts.
6. Small, boring infrastructure: one Go binary, one database.

## Development

```bash
go build ./... && go test ./...     # backend
cd frontend && npm run build        # frontend
```

Requires Go 1.26+, Node 22+, Docker (for PostgreSQL and the scanner runtime).

## License

MIT
