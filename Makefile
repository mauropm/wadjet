# WADJET — build & development entry points.
#
#   make          full build: Go server binary + production frontend bundle
#   make dev      local development WITHOUT login (API :8080 + Vite :5173)
#   make stop     kill all WADJET servers (API, Vite) and remove dev pid files
#   make clean    remove build artifacts (bin/, frontend/dist/, dev logs)
#
# Extra helpers: make test, make run, make db, make status.

BIN      := bin/server
GO       ?= go
NPM      ?= npm

# Local development defaults (docker-compose postgres by default).
DEV_DB           ?= postgres://wadjet:***@127.0.0.1:5432/wadjet?sslmode=disable
DEV_PORT         ?= 8080
DEV_ADMIN_EMAIL  ?= admin@wadjet.local

DEV_ENV = DATABASE_URL='$(DEV_DB)' \
          WADJET_ENV=development \
          WADJET_DEV_NO_LOGIN=1 \
          WADJET_PORT=$(DEV_PORT) \
          WADJET_ADMIN_EMAIL=$(DEV_ADMIN_EMAIL) \
          WADJET_REPORT_DIR=./data/reports \
          WADJET_RAW_OUTPUT_DIR=./data/raw \
          WADJET_SCAN_WORKDIR=./data/scanwork

SERVER_PID := .dev-server.pid

.DEFAULT_GOAL := all
.PHONY: all build frontend test db dev dev-local run stop clean status

## make (default): full build — server binary + frontend bundle.
all: build frontend

build:
	$(GO) build -o $(BIN) ./cmd/server

frontend:
	cd frontend && $(NPM) install && $(NPM) run build

test:
	$(GO) test ./... -count=1

## Ensure the local postgres container is up (docker-compose).
db:
	docker compose up -d postgres

## Local development WITHOUT login: starts the API impersonating the
## bootstrap admin (WADJET_DEV_NO_LOGIN=1, development mode only, bound to
## 127.0.0.1) and the Vite dev server with hot reload. Ctrl-C stops both.
## If $(DEV_PORT) is held by another process (e.g. a docker container),
## the API auto-bumps to the next free port and Vite's /api proxy follows.
## Need the API on the LAN anyway? WADJET_DEV_BIND_ALL=1 make dev.
dev: build
	@mkdir -p data/reports data/raw data/scanwork
	@PORT=$(DEV_PORT); \
	while lsof -nP -iTCP:$$PORT -sTCP:LISTEN >/dev/null 2>&1; do \
		PORT=$$((PORT+1)); \
		if [ $$PORT -gt $$(($(DEV_PORT)+19)) ]; then echo "✗ no free API port in $(DEV_PORT)..$$(($(DEV_PORT)+19))"; exit 1; fi; \
	done; \
	if [ "$$PORT" != "$(DEV_PORT)" ]; then echo "note: :$(DEV_PORT) is held by another process — API uses :$$PORT"; fi; \
	$(DEV_ENV) WADJET_PORT=$$PORT $(CURDIR)/$(BIN) > .dev-server.log 2>&1 & echo $$! > $(SERVER_PID); \
	sleep 1; \
	if ! kill -0 $$(cat $(SERVER_PID)) 2>/dev/null; then \
		echo "✗ API failed to start — last log lines:"; tail -5 .dev-server.log; rm -f $(SERVER_PID); exit 1; \
	fi; \
	echo "👁️  WADJET dev (NO LOGIN — you are $(DEV_ADMIN_EMAIL), no usr/pass asked)"; \
	echo "   API  http://127.0.0.1:$$PORT/api/v1"; \
	echo "   UI   http://127.0.0.1:5173"; \
	echo "   log  .dev-server.log   (Ctrl-C stops both)"; \
	trap 'PID=$$(cat $(SERVER_PID) 2>/dev/null); [ -n "$$PID" ] && kill $$PID 2>/dev/null; rm -f $(SERVER_PID); exit 0' INT TERM; \
	(cd frontend && [ -d node_modules ] || $(NPM) install; WADJET_API_PORT=$$PORT $(NPM) run dev); \
	PID=$$(cat $(SERVER_PID) 2>/dev/null); [ -n "$$PID" ] && kill $$PID 2>/dev/null; rm -f $(SERVER_PID); true

## Alias for `make dev` — same no-login local development stack.
dev-local: dev

## Run the built binary (real auth) with development defaults.
run: build
	@mkdir -p data/reports data/raw data/scanwork
	$(DEV_ENV) WADJET_DEV_NO_LOGIN= $(CURDIR)/$(BIN)

## Kill all WADJET servers started by dev/run (never touches postgres).
## Matches are anchored to this checkout's absolute path, so other
## projects' servers are untouchable.
stop:
	@test -f $(SERVER_PID) && kill $$(cat $(SERVER_PID)) 2>/dev/null || true
	@rm -f $(SERVER_PID)
	@pkill -f '^$(CURDIR)/bin/server' 2>/dev/null || true
	@pkill -f 'node $(CURDIR)/frontend/node_modules/.*vite' 2>/dev/null || true
	@echo "✓ all WADJET servers stopped"

status:
	@pgrep -fl '^$(CURDIR)/bin/server' || echo "no API server running"
	@pgrep -f '$(CURDIR)/frontend/node_modules' >/dev/null && echo "vite dev server running" || echo "no vite dev server"

## Remove build artifacts. Does NOT delete ./data (persisted reports,
## raw scan output) or the database — remove those explicitly if desired.
clean: stop
	rm -rf bin frontend/dist .dev-server.log .dev-server.pid
	@echo "✓ cleaned build artifacts"
