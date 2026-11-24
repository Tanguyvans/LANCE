#!/usr/bin/env bash
# Automated Level-1 installation check for a containerized LANCE deployment.
#
# Run from the directory containing docker-compose.yml and .env after
# `docker compose up -d`. Checks container health, .env syntax, local
# provider reconciliation, local Ollama embeddings (no Voyage cloud errors),
# dashboard loopback availability, Ollama connectivity from inside the
# container, required network binaries, and loopback-only LAN isolation.
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
SERVICE="${SERVICE:-nato-iot}"
DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:8000}"

PASS=0
WARN=0
FAIL=0

pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
warn() { printf '  [WARN] %s\n' "$1"; WARN=$((WARN + 1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }

read_env() {
  local key="$1"
  [ -f "$ENV_FILE" ] || return 0
  awk -F= -v k="$key" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    $1 == k { sub(/^[^=]*=/, ""); print; exit }
  ' "$ENV_FILE"
}

echo "=== LANCE installation verification ==="

# 1. .env presence and inline-comment sanity
if [ -f "$ENV_FILE" ]; then
  if grep -nE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=.*#' "$ENV_FILE" >/dev/null 2>&1; then
    fail ".env contains inline '#' comments on KEY=value lines (Docker Compose includes them in values)"
  else
    pass ".env present with clean syntax (no inline '#' comments)"
  fi
else
  fail ".env not found in $(pwd) — copy .env.example to .env first"
fi

PROVIDER="$(read_env AGENT_PROVIDER)"
LLM_URL="$(read_env LANCE_LLM_BASE_URL)"
[ -n "$LLM_URL" ] || LLM_URL="$(read_env LANCE_MOE_BASE_URL)"
[ -n "$LLM_URL" ] || LLM_URL="http://localhost:11434/v1"
LLM_MODEL="$(read_env LANCE_LLM_MODEL)"
[ -n "$LLM_MODEL" ] || LLM_MODEL="$(read_env LANCE_MOE_MODEL)"
EMBED_URL="$(read_env LANCE_EMBED_BASE_URL)"
[ -n "$EMBED_URL" ] || EMBED_URL="$LLM_URL"
EMBED_MODEL="$(read_env LANCE_EMBED_MODEL)"
[ -n "$EMBED_MODEL" ] || EMBED_MODEL="nomic-embed-text"
BIND_HOST="$(read_env LANCE_BIND_HOST)"
[ -n "$BIND_HOST" ] || BIND_HOST="127.0.0.1"
ADMIN_TOKEN="$(read_env LANCE_ADMIN_TOKEN)"

# 2. Container running and healthy
CID="$(docker compose ps -q "$SERVICE" 2>/dev/null || true)"
if [ -z "$CID" ]; then
  fail "Container '$SERVICE' is not running (run: docker compose up -d)"
else
  STATUS="$(docker inspect --format '{{.State.Status}}' "$CID" 2>/dev/null || echo unknown)"
  HEALTH="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CID" 2>/dev/null || echo unknown)"
  if [ "$STATUS" = "running" ] && [ "$HEALTH" = "healthy" ]; then
    pass "Container '$SERVICE' is running and healthy"
  elif [ "$STATUS" = "running" ] && [ "$HEALTH" = "starting" ]; then
    warn "Container '$SERVICE' is still starting (first-boot knowledge ingest can take 1-3 min)"
  else
    fail "Container '$SERVICE' state=${STATUS}, health=${HEALTH}"
  fi
fi

# 3. Boot logs: provider reconciled + local ingest with no Voyage error
LOGS="$(docker compose logs --no-color "$SERVICE" 2>/dev/null || true)"
if printf '%s\n' "$LOGS" | grep -q '\[reconcile\] provider '; then
  RECONCILE_LINE="$(printf '%s\n' "$LOGS" | grep '\[reconcile\] provider ' | tail -n 1)"
  pass "Provider reconciled from .env (${RECONCILE_LINE#*\[reconcile\] })"
else
  fail "No '[reconcile] provider ...' line in container logs"
fi

if printf '%s\n' "$LOGS" | grep -q 'VOYAGE_API_KEY not set'; then
  fail "Container logs contain 'VOYAGE_API_KEY not set' (embeddings did not stay local)"
elif printf '%s\n' "$LOGS" | grep -qE '\[init\] Ingested [0-9]+ skill chunks|Knowledge store ready'; then
  pass "Local knowledge store ingested without Voyage cloud dependency"
elif [ -f "./data/.initialized" ]; then
  pass "Local knowledge store already initialized (./data/.initialized present)"
else
  warn "Knowledge store ingest not yet confirmed in logs (still starting?)"
fi

# 4. Dashboard HTTP 200 on loopback
HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "${DASHBOARD_URL}/" 2>/dev/null || echo 000)"
if [ "$HTTP_CODE" = "200" ]; then
  pass "Dashboard reachable at ${DASHBOARD_URL}/ (HTTP 200)"
else
  fail "Dashboard unreachable at ${DASHBOARD_URL}/ (HTTP ${HTTP_CODE})"
fi

# 5. Model registered in /api/models
if [ -n "$LLM_MODEL" ]; then
  MODELS_JSON="$(curl -sS --max-time 5 "${DASHBOARD_URL}/api/models" 2>/dev/null || true)"
  if printf '%s' "$MODELS_JSON" | grep -Fq "$LLM_MODEL"; then
    pass "Model '${LLM_MODEL}' registered in /api/models"
  else
    fail "Model '${LLM_MODEL}' not found in /api/models"
  fi
else
  warn "LANCE_LLM_MODEL is empty in .env — skipping /api/models check"
fi

# 6. Ollama reachability + models check from inside the container
if [ -n "$CID" ]; then
  OLLAMA_MODELS="$(docker compose exec -T "$SERVICE" curl -fsS --max-time 5 "${LLM_URL%/}/models" 2>/dev/null || true)"
  if [ -n "$OLLAMA_MODELS" ]; then
    pass "Ollama endpoint reachable from container (${LLM_URL%/}/models)"
    if [ -n "$LLM_MODEL" ]; then
      if printf '%s' "$OLLAMA_MODELS" | grep -Fq "$LLM_MODEL"; then
        pass "Chat model '${LLM_MODEL}' is served by Ollama"
      else
        fail "Chat model '${LLM_MODEL}' not served by Ollama (run: ollama pull ${LLM_MODEL})"
      fi
    fi
  else
    fail "Cannot reach Ollama at ${LLM_URL%/}/models from inside container"
  fi

  EMBED_MODELS="$OLLAMA_MODELS"
  if [ "${EMBED_URL%/}" != "${LLM_URL%/}" ]; then
    EMBED_MODELS="$(docker compose exec -T "$SERVICE" curl -fsS --max-time 5 "${EMBED_URL%/}/models" 2>/dev/null || true)"
  fi
  if printf '%s' "$EMBED_MODELS" | grep -Fq "$EMBED_MODEL"; then
    pass "Embedding model '${EMBED_MODEL}' is served by Ollama"
  else
    fail "Embedding model '${EMBED_MODEL}' not served by Ollama at ${EMBED_URL} (run: ollama pull ${EMBED_MODEL})"
  fi

  # 7. Required network binaries inside the container
  MISSING_BINS="$(docker compose exec -T "$SERVICE" sh -c '
    for b in nmap ip traceroute ping curl ssh; do
      command -v "$b" >/dev/null 2>&1 || printf "%s " "$b"
    done
  ' 2>/dev/null || echo "exec-failed")"
  if [ -z "${MISSING_BINS// /}" ]; then
    pass "Required network binaries present in container (nmap, ip, traceroute, ping, curl, ssh)"
  else
    fail "Missing binaries inside container: ${MISSING_BINS}"
  fi
fi

# 8. Security posture
if [ "$BIND_HOST" = "127.0.0.1" ] || [ "$BIND_HOST" = "localhost" ]; then
  pass "Dashboard bound to loopback only (LANCE_BIND_HOST=${BIND_HOST})"
else
  warn "LANCE_BIND_HOST=${BIND_HOST} (dashboard may be exposed on LAN; use 127.0.0.1 in host mode)"
fi

if [ -n "$ADMIN_TOKEN" ]; then
  pass "LANCE_ADMIN_TOKEN is set"
else
  warn "LANCE_ADMIN_TOKEN is empty (fine for local smoke test; set a random token for partner deploys)"
fi

echo ""
echo "Summary: ${PASS} passed, ${WARN} warning(s), ${FAIL} failed."
[ "$FAIL" -eq 0 ]
