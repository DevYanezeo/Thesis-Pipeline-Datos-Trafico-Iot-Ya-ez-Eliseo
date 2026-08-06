# Pipeline de datos — tráfico IoT (smarthome)

Paquete Python **downstream** que transforma capturas de tráfico IoT y sus eventos asociados en un dataset de flujos etiquetados, persistido en Apache Parquet.

**Entrada:** PCAP + JSON de eventos (contrato con la capa de orquestación experimental).  
**Salida:** `flows.parquet`, manifiesto, reporte evento↔flujo; opcionalmente paquete ML sin fuga de datos.

> Este repositorio contiene **únicamente** el desarrollo del pipeline (código, tests, contrato y guías de uso). No incluye el documento de tesis, capturas grandes ni salidas de corridas.

## Requisitos

- Python 3.11+
- Linux o WSL Ubuntu (NFStream nativo; es el **único** extractor soportado)
- Dependencias en `requirements.txt` / `pyproject.toml`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
# opcional, horizontes N-paquetes:
pip install -e ".[horizon]"
```

## Estructura

```text
pipeline/           # Paquete instalable (CLI + módulos)
tests/              # Suite pytest (contrato, etiquetado, ML, CLI)
fixtures/           # JSON de ejemplo (PCAPs locales, no versionados)
sample_data/        # CSV auxiliar mínimo para tests
docs/
  ARCHITECTURE.md         # Módulos, flujo y criterios ISO/IEC 25010
  CONTRATO-INTEGRACION.md # Contrato PCAP + JSON upstream
  GUIA-PRUEBAS-ML.md      # Handoff preprocess-ml / validate_ml
scripts/            # Utilidades (WSL, merge multi-PCAP)
```

Detalle de módulos y calidad: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Uso rápido

```bash
python -m pipeline run \
  --pcap fixtures/upstream-run-00/capture.pcap \
  --metadata fixtures/upstream-run-00/metadata.json \
  --output output/run01/ \
  --packet-horizons 5,10,20 \
  --idle-timeout 120 \
  --active-timeout 1800 \
  --n-dissections 20 \
  --evaluate
```

Multi-segmento: `--artifact-pcap-dir <dir>` en lugar de `--pcap`.

Handoff ML (anti-fuga):

```bash
python -m pipeline preprocess-ml \
  --input output/run01/flows.parquet \
  --output output/run01/ml-handoff/ \
  --split-by episode \
  --classes three-class
```

Ver [`docs/GUIA-PRUEBAS-ML.md`](docs/GUIA-PRUEBAS-ML.md).

## Artefactos de salida

| Archivo | Descripción |
|---------|-------------|
| `flows.parquet` | Flujos etiquetados (persistencia analítica) |
| `flows_baseline.csv` | Baseline CSV para contraste I/O |
| `manifest.json` | Parámetros y conteos de la corrida |
| `traceability_report.json` | Calidad del *ground truth* (evento↔flujo) |
| `io_metrics.json` | Compresión / *speedup* (con `--evaluate`) |

## Contrato de integración

El contrato oficial es **PCAP + JSON de eventos**. El CSV no sustituye al JSON.

Esquema mínimo y checklist: [`docs/CONTRATO-INTEGRACION.md`](docs/CONTRATO-INTEGRACION.md).

## Tests

```bash
pytest -q
```

## Calidad

La verificación del producto se alinea con dimensiones de **ISO/IEC 25010** (funcionalidad, eficiencia, fiabilidad, usabilidad, seguridad, mantenibilidad, compatibilidad). Ver tabla en [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Licencia

MIT (ver `pyproject.toml`). Trabajo de título — DIINF, Universidad de Santiago de Chile.
