#!/usr/bin/env bash
# E2E smoke test: complete WADJET workflow through the real HTTP API.
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080/api/v1}"
J() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)" 2>/dev/null || echo PARSE_FAIL; }

echo "== health"
curl -sf "$BASE/../../healthz" >/dev/null && echo "healthz OK"

echo "== login"
TOKEN=$(curl -sf -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"${ADMIN_EMAIL:-admin@wadjet.local}\",\"password\":\"${ADMIN_PW}\"}" | J "['token']")
[ -n "$TOKEN" ] && [ "$TOKEN" != "PARSE_FAIL" ] || { echo "LOGIN FAILED"; exit 1; }
AUTH="Authorization: Bearer $TOKEN"
echo "token OK"

echo "== create project"
PID=$(curl -sf -X POST "$BASE/projects" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"E2E Smoke","description":"smoke","tags":["e2e"]}' | J "['id']")

echo "== add authorized target (localhost) + excluded"
curl -sf -X POST "$BASE/projects/$PID/targets" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","target_type":"ip","excluded":false}' >/dev/null
curl -sf -X POST "$BASE/projects/$PID/targets" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"target":"8.8.8.8","target_type":"ip","excluded":true}' >/dev/null

echo "== clone project (settings/targets/profiles)"
CID=$(curl -sf -X POST "$BASE/projects/$PID/clone" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"E2E Clone","description":"cloned smoke","copy":{"settings":true,"targets":true,"profiles":true,"tags":true}}' | J "['id']")
[ -n "$CID" ] && [ "$CID" != "PARSE_FAIL" ] && echo "clone OK ($CID)" || { echo "CLONE FAILED"; exit 1; }
[ "$CID" != "$PID" ] && echo "clone got independent ID"
NT=$(curl -sf "$BASE/projects/$CID/targets" -H "$AUTH" | J "['total']")
[ "${NT:-0}" -ge 1 ] && echo "clone carried $NT target(s)" || { echo "CLONE MISSING TARGETS"; exit 1; }

echo "== list scanners"
curl -sf "$BASE/scanners" -H "$AUTH" | python3 -c "import sys,json;d=json.load(sys.stdin);names=[s['name'] for s in d['items']];assert 'nmap' in names, names;print('registry loaded:',names)"

echo "== scope gate: unauthorized target must be refused at creation"
BAD=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/projects/$PID/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"bad","targets":["9.9.9.9"],"scanner_configs":[{"scanner":"nmap","config":{}}]}')
[ "$BAD" = "400" ] || [ "$BAD" = "403" ] && echo "unauthorized target refused ($BAD)" || { echo "SCOPE GATE WEAK: $BAD"; exit 1; }
BADX=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/projects/$PID/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"badx","targets":["8.8.8.8"],"scanner_configs":[{"scanner":"nmap","config":{}}]}')
[ "$BADX" = "400" ] || [ "$BADX" = "403" ] && echo "excluded target refused ($BADX)" || { echo "EXCLUSION GATE WEAK: $BADX"; exit 1; }

echo "== launch real scan (loopback, top ports, safe scripts)"
SID=$(curl -sf -X POST "$BASE/projects/$PID/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"smoke scan","targets":["127.0.0.1"],"scanner_configs":[{"scanner":"nmap","config":{"scan_intensity":"top1000","service_detection":true,"skip_ping":true,"script_categories":["safe"]}}]}' | J "['id']")
curl -sf -X POST "$BASE/scans/$SID/start" -H "$AUTH" >/dev/null && echo "scan $SID started"

echo "== wait for completion"
for i in $(seq 1 60); do
  ST=$(curl -sf "$BASE/scans/$SID" -H "$AUTH" | J "['status']")
  case "$ST" in completed|completed_with_errors|failed|cancelled) break;; esac
  sleep 3
done
curl -sf "$BASE/scans/$SID" -H "$AUTH" | python3 -c "import sys,json;d=json.load(sys.stdin);print('status:',d['status'],'| assets:',d['assets_processed'],'| findings:',d['findings_created'],'| execs:',[(e['scanner_name'],e['status']) for e in d.get('executions',[])])"

echo "== findings persisted"
curl -sf "$BASE/projects/$PID/findings" -H "$AUTH" | python3 -c "import sys,json;d=json.load(sys.stdin);items=d['items'];print('findings total:',d['total']);[print(' -',f['severity'],f['title'][:60],'@',f['fingerprint'][:8]) for f in items[:5]]"

echo "== assets + history"
curl -sf "$BASE/projects/$PID/assets" -H "$AUTH" | python3 -c "import sys,json;d=json.load(sys.stdin);print('assets:',d['total']);a=d['items'][0];print(' first asset:',a['identity'],a['discovery_source'])" 
AID=$(curl -sf "$BASE/projects/$PID/assets" -H "$AUTH" | J "['items'][0]['id']")
curl -sf "$BASE/assets/$AID/history" -H "$AUTH" | J "['total']" | grep -qv 0 && echo "observation history OK"

echo "== reports"
RID=$(curl -sf -X POST "$BASE/projects/$PID/reports/scan" -H "$AUTH" -H 'Content-Type: application/json' -d "{\"session_id\":\"$SID\"}" | J "['id']")
FID=$(curl -sf "$BASE/projects/$PID/findings" -H "$AUTH" | J "['items'][0]['id']")
curl -sf -X POST "$BASE/findings/$FID/report" -H "$AUTH" >/dev/null
CONID=$(curl -sf -X POST "$BASE/projects/$PID/reports/findings" -H "$AUTH" -H 'Content-Type: application/json' -d '{"consolidated":true}' | J "['id']")
ZIPID=$(curl -sf -X POST "$BASE/projects/$PID/reports/findings" -H "$AUTH" -H 'Content-Type: application/json' -d '{"consolidated":false}' | J "['id']")
for i in $(seq 1 20); do
  N=$(curl -sf "$BASE/reports?project_id=$PID" -H "$AUTH" | python3 -c "import sys,json;d=json.load(sys.stdin);print(sum(1 for r in d['items'] if r['status']=='completed'))")
  [ "$N" -ge 4 ] && break; sleep 2
done
curl -sf "$BASE/reports?project_id=$PID" -H "$AUTH" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(' report:',r['type'],r['status'],r['file_size'],'bytes') for r in d['items']]"
curl -sf "$BASE/reports/$RID/download" -H "$AUTH" -o /tmp/e2e-scan.pdf && head -c 4 /tmp/e2e-scan.pdf | grep -q '%PDF' && echo "scan PDF OK ($(stat -f%z /tmp/e2e-scan.pdf) bytes)"
curl -sf "$BASE/reports/$CONID/download" -H "$AUTH" -o /tmp/e2e-consolidated.pdf && head -c 4 /tmp/e2e-consolidated.pdf | grep -q '%PDF' && echo "consolidated PDF OK ($(stat -f%z /tmp/e2e-consolidated.pdf) bytes)"
curl -sf "$BASE/reports/$ZIPID/download" -H "$AUTH" -o /tmp/e2e-findings.zip && unzip -l /tmp/e2e-findings.zip | tail -3

echo "E2E COMPLETE"
