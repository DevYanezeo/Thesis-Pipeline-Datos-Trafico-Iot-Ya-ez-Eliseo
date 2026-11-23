#!/usr/bin/env bash
# Entorno virtual del pipeline (Manjaro/Arch: no usar pip en el Python del sistema, PEP 668).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-/usr/bin/python3.14}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON=/usr/bin/python3
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "No se encontró Python del sistema. Exporte PYTHON=/usr/bin/python3.14" >&2
  exit 1
fi

# Si `python` del PATH es Cursor, el venv enlazado hereda el intérprete equivocado.
_bad_venv() {
  [[ ! -d .venv/bin ]] && return 1
  if [[ -L .venv/bin/python ]] && readlink .venv/bin/python 2>/dev/null | grep -qi cursor; then
    return 0
  fi
  if .venv/bin/python -c "import sys; print(sys.executable)" 2>/dev/null | grep -qi cursor; then
    return 0
  fi
  return 1
}

if [[ -d .venv ]] && _bad_venv; then
  echo "Eliminando .venv inválido (intérprete enlazado a Cursor)…"
  rm -rf .venv
fi

echo "==> Creando .venv con $PYTHON (--copies)"
"$PYTHON" -m venv --copies .venv

EXTRAS="dev,ui"
for arg in "$@"; do
  case "$arg" in
    --notebook|--all)
      EXTRAS="dev,ui,notebook"
      ;;
    --help|-h)
      echo "Uso: bash scripts/setup-venv.sh [--notebook|--all]"
      echo "  Por defecto instala [dev,ui]. Con --notebook añade Jupyter Lab para el cuaderno demo."
      exit 0
      ;;
  esac
done

echo "==> pip install -e \".[$EXTRAS]\""
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[$EXTRAS]"

echo ""
echo "Listo. Elija interfaz (misma lógica del pipeline en todas):"
echo "  TUI (logs en terminal) : bash scripts/pipeline-ui.sh"
if [[ "$EXTRAS" == *notebook* ]]; then
  echo "  Jupyter (cuaderno demo): bash scripts/jupyter-demo.sh"
else
  echo "  Jupyter              : bash scripts/setup-venv.sh --notebook  # y luego jupyter-demo.sh"
fi
echo "  CLI                  : source .venv/bin/activate && python -m pipeline run ..."