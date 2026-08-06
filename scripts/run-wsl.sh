#!/bin/sh
# Corrida piloto en WSL Ubuntu con NFStream (JSON nativo).
# Uso: bash scripts/run-wsl.sh
# Requiere: fixtures/upstream-run-00/capture.pcap + metadata.json

set -e
cd "$(dirname "$0")/.."

echo "==> Ejecutar pipeline (NFStream, contrato JSON)"
python3 -m pipeline run \
  --pcap fixtures/upstream-run-00/capture.pcap \
  --metadata fixtures/upstream-run-00/metadata.json \
  --output output/00-run01-wsl/ \
  --evaluate --verbose

echo "==> Listo. Ver output/00-run01-wsl/manifest.json"
