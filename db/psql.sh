#!/usr/bin/env bash
# Abre psql contra la BBDD de Azure con las credenciales de .env (no las muestra).
# Uso: db/psql.sh            -> consola interactiva
#      db/psql.sh -c "SQL"   -> ejecuta una consulta
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
export PGSSLMODE=require
exec psql "$@"
