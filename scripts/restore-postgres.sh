#!/usr/bin/env sh
set -eu

: "${RESTORE_DATABASE_URL:?set RESTORE_DATABASE_URL}"
: "${BACKUP_FILE:?set BACKUP_FILE}"

pg_restore --clean --if-exists --dbname "$RESTORE_DATABASE_URL" "$BACKUP_FILE"

echo "restored $BACKUP_FILE"
