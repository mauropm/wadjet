# WADJET Demonstration Lab

A self-contained, **deliberately vulnerable** target environment for
demonstrating WADJET's scanning and reporting pipeline — plus the seed CLI
that provisions its project, targets, profiles and manual assets.

> ⚠️ **These services are intentionally insecure.** Juice Shop and WebGoat
> are real, exploitable applications. Everything here lives on the private,
> **internal** Docker network `wadjet-lab` (`internal: true`) and **nothing
> publishes a host port**. There is deliberately no way to reach the lab from
> the internet or from your host stack unless you explicitly join a container
> to `wadjet-lab`. Do not "fix" that isolation by adding `ports:` mappings.

## 1. Start the lab

```bash
docker compose -f demo/docker-compose.yml up -d
docker compose -f demo/docker-compose.yml ps        # wait for (healthy)
```

| Container | Service | Port (lab-internal) | What to expect from a scan |
|---|---|---|---|
| `wadjet-lab-juice-shop` | OWASP Juice Shop | 3000 | Full-featured vulnerable SPA: CORS misconfig, XSS-prone endpoints, `/ftp`, `/api` (jwt weak secrets), `X-Frame-Options` missing… |
| `wadjet-lab-webgoat` | OWASP WebGoat | 8080 | Training app; verbose Spring errors, `/webgoat/*` attack surfaces |
| `wadjet-lab-http-banner` | nginx (banner-rich) | 80 | Exact version disclosure (`nginx/1.27.x`), `X-Powered-By`, debug headers, `/admin` comment in HTML |
| `wadjet-lab-tls-test` | nginx (TLS) | 443 | Self-signed cert (CN=tls.lab), **TLS 1.0/1.1 enabled**, weak cipher list at SECLEVEL=1 |
| `wadjet-lab-sshd` | openssh (linuxserver) | 2222 | Custom banner advertising an old 2017 firmware build, password auth with `lab/labpassword` |
| `wadjet-lab-noisy` | socat listeners | 8000–8005 | Six chatty TCP services with fake build strings — always gives a port sweep something to find |

All services define healthchecks; a container stuck `unhealthy` usually just
needs more `start_period` time on first pull.

## 2. Seed the WADJET demo project (no findings!)

```bash
go run ./demo/seed              # idempotent — creates "🧪 WADJET Demo Lab"
go run ./demo/seed --cleanup    # remove it again
```

The seed creates:

* the demo project (description clearly marks it as demo data),
* **6 authorized targets** — the lab service names (`juice-shop`,
  `webgoat`, `http-banner`, `tls-test`, `sshd`, `noisy`) — plus one
  **excluded** canary target (`198.51.100.0/24`) that must never be scanned,
* two scan profiles, **Quick Discovery** and **Standard Assessment**, bound
  to the `nmap` scanner (config JSON follows the nmap adapter conventions
  owned by Agent 2),
* two manually-discovered assets (`discovery_source='manual'`, tag `demo`).

It **never seeds fake findings**: findings appear only after you run a real
scan through WADJET against the lab, exactly as in production.

## 3. Point WADJET at the lab

### Option A — from the WADJET container (recommended)

The root `docker-compose.yml` already attaches the `wadjet` service to the
shared `wadjet-lab` network, and its image ships `nmap` + NSE scripts:

```bash
docker compose up -d            # WADJET + Postgres (creates wadjet-lab if absent)
docker compose -f demo/docker-compose.yml up -d   # the lab itself
```

Then log in (default `admin@wadjet.local` / `admin`), open the
*🧪 WADJET Demo Lab* project, start a scan with the **Standard Assessment**
profile against the seeded targets, and download the report when the session
completes.

### Option B — from a throwaway nmap container (quick manual verification)

```bash
docker run --rm -it --network wadjet-lab alpine/nmap \
  -sV -sC --version-intensity 5 172.30.0.0/24
```

(Use the service names too — Docker's DNS resolves them on that network:
`nmap juice-shop tls-test sshd -p 2222`.)

## 4. What NSE will find (talking points)

* `ssl-cert` / `ssl-enum-ciphers` on `tls-test:443` — self-signed cert,
  deprecated TLS 1.0/1.1, weak suites.
* `http-headers`, `http-server-header`, `http-title` on the banner endpoints
  — version disclosure, `X-Powered-By`, debug headers.
* `ssh-brute`/`sshv1` on `sshd:2222` — banner claims a 2017 OpenSSH-era
  firmware; password auth enabled (the banner names the demo credential).
* `http-enum` — Juice Shop's `/ftp`, `/b2b/wall`, `/api`; WebGoat's
  `/webgoat/` landing pages.
* `banner`/`fingerprint` hits on the six `noisy:8000-8005` listeners with
  their fake `v1.3.37-alpha (UNPATCHED)` strings.

## 5. Teardown

```bash
docker compose -f demo/docker-compose.yml down -v   # lab (removes tls-certs volume)
go run ./demo/seed --cleanup                        # demo project in the DB
```

## Notes & known edges

* **No egress for lab containers.** `internal: true` blocks internet access
  for the lab (by design). The tls-test container therefore generates its
  self-signed cert with an *in-image* `openssl` when available; nginx's
  busybox `wget` healthchecks are TLS-capable. If an image's healthcheck
  tool is missing (WebGoat images vary), the container still serves — check
  `docker compose -f demo/docker-compose.yml logs -f <svc>`.
* Profiles store nmap options as JSON (`ports`, `scripts`, `os_detect`,
  `timing`); the orchestrator (Agent 2) interprets them. The seed only
  records them — it does not invoke scanners.
* The `noisy` container uses the published `alpine/socat` image, so no
  packages are installed at runtime (nothing needs egress).
