#!/usr/bin/env bash
# Jupyter Lab con el cuaderno de demo (mismo venv que la TUI / CLI).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
NB="$ROOT/notebooks/pipeline_demo.ipynb"

if [[ ! -x "$PY" ]]; then
  echo "No existe $PY. Ejecute: bash scripts/setup-venv.sh --notebook" >&2
  exit 1
fi

if ! "$PY" -c "import jupyterlab" 2>/dev/null; then
  echo "Falta Jupyter. Ejecute: bash scripts/setup-venv.sh --notebook" >&2
  exit 1
fi

exec "$PY" -m jupyter lab "$NB" "$@"