#!/usr/bin/env sh
set -eu

: "${DATABASE_URL:?set DATABASE_URL}"

BACKUP_DIR="${BACKUP_DIR:-./backups}"
STAMP="$(date +%Y%m%d%H%M%S)"
OUT="${OUT:-${BACKUP_DIR}/authservice-${STAMP}.dump}"

mkdir -p "$BACKUP_DIR"
pg_dump "$DATABASE_URL" --format=custom --file "$OUT"

echo "wrote $OUT"
