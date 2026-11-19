# ─────────────────────────────────────────────────────────────────────────────
# WADJET — multi-stage production image.
#
#   Build:  docker build -t wadjet .
#   Run:    docker compose up          (preferred — see docker-compose.yml)
#
# The final image ships nmap + NSE scripts because WADJET executes real
# scanners inside this container. The app runs as a non-root user; nmap then
# performs TCP connect scans (no raw SYN without NET_RAW — grant the
# capability in compose if SYN scans are required).
# ─────────────────────────────────────────────────────────────────────────────

# Overridable bases (air-gapped / registry-restricted builds):
#   docker build --build-arg RUNTIME_BASE=alpine:latest .
ARG BUILD_BASE=golang:1.26-alpine
ARG RUNTIME_BASE=alpine:3.22

# ---------- build stage -----------------------------------------------------
FROM ${BUILD_BASE} AS build

WORKDIR /src

# Dependency layer (cached unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/wadjet ./cmd/server

# ---------- runtime stage ---------------------------------------------------
FROM ${RUNTIME_BASE}

# nmap + scripting engine for real scans; ca-certificates for TLS checks.
RUN apk add --no-cache \
        nmap \
        nmap-scripts \
        ca-certificates \
        tzdata \
    && adduser -D -H -u 10001 -h /app wadjet

WORKDIR /app

COPY --from=build /out/wadjet /app/wadjet

# Persistent state: reports, raw scanner output, scan work dirs.
RUN mkdir -p /app/data && chown -R wadjet:wadjet /app
VOLUME ["/app/data"]

USER wadjet

ENV WADJET_ENV=production \
    WADJET_PORT=8080 \
    WADJET_REPORT_DIR=/app/data/reports \
    WADJET_RAW_OUTPUT_DIR=/app/data/raw \
    WADJET_SCAN_WORKDIR=/app/data/scanwork \
    WADJET_SCANNER_CONFIG_DIR=/app/configs/scanners

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/wadjet"]
