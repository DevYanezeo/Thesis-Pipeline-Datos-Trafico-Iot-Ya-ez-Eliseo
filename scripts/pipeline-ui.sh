#!/usr/bin/env bash
# Lanza la consola TUI con el Python del venv (evita `python` del PATH apuntando a Cursor).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "No existe $PY. Ejecute: bash scripts/setup-venv.sh" >&2
  exit 1
fi
exec "$PY" -m pipeline ui "$@"