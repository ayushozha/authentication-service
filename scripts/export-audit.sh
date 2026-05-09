#!/usr/bin/env sh
set -eu

: "${BASE_URL:?set BASE_URL}"
: "${ADMIN_API_KEY:?set ADMIN_API_KEY}"

FORMAT="${FORMAT:-jsonl}"
LIMIT="${LIMIT:-500}"
CLIENT_ID="${CLIENT_ID:-}"
EVENT_TYPE="${EVENT_TYPE:-}"
USER_ID="${USER_ID:-}"
OUT="${OUT:-authservice-audit-events.${FORMAT}}"

QUERY="format=${FORMAT}&limit=${LIMIT}"
[ -n "$CLIENT_ID" ] && QUERY="${QUERY}&client_id=${CLIENT_ID}"
[ -n "$EVENT_TYPE" ] && QUERY="${QUERY}&event_type=${EVENT_TYPE}"
[ -n "$USER_ID" ] && QUERY="${QUERY}&user_id=${USER_ID}"

curl "${BASE_URL%/}/api/admin/audit-events/export?${QUERY}" \
  -H "X-Admin-Key: ${ADMIN_API_KEY}" \
  -o "$OUT"

echo "wrote $OUT"
