# Pipeline de datos para tráfico IoT en entornos smarthome

Repositorio de **implementación** del Trabajo de Título de Eliseo Sebastián Yáñez Robles  
(Ingeniería de Ejecución en Computación e Informática — DIINF, Universidad de Santiago de Chile).  
Profesor guía: Juan Ignacio Iturbe Araya.

El trabajo desarrolla un **pipeline de datos** que, a partir de capturas de red de un hogar inteligente (archivos PCAP) y del registro de eventos de la capa de orquestación experimental (JSON), produce un dataset de flujos de red etiquetados y persistidos en Apache Parquet. El objetivo es entregar un insumo reproducible —con origen documentado entre evento y flujo, y con menor costo de almacenamiento/lectura que un CSV plano— para investigaciones posteriores en detección de anomalías, **sin** entrenar el IDS dentro de este proyecto.

El pipeline opera **aguas abajo** (*downstream*): no orquesta escenarios, no inyecta ataques y no captura el tráfico en el testbed. Esas responsabilidades quedan en la capa *upstream*; aquí solo se ingieren sus artefactos, se extraen flujos con NFStream, se etiquetan y se persisten.

Este repositorio contiene el **código, las pruebas y la documentación técnica** del software. El documento de tesis, las capturas grandes y las salidas de corridas no se versionan aquí.

**Entrada:** PCAP + JSON de eventos.  
**Salida:** `flows.parquet`, manifiesto, reporte evento↔flujo; opcionalmente un paquete listo para ML sin fuga de datos.

## Requisitos

- Python 3.11+
- Linux o WSL Ubuntu (NFStream nativo; es el **único** extractor soportado)
- Dependencias en `requirements.txt` / `pyproject.toml`

En **Manjaro/Arch** no use `pip` contra el Python del sistema (error PEP 668). Use el script del repo:

```bash
bash scripts/setup-venv.sh
source .venv/bin/activate
```

Equivalente manual (con `/usr/bin/python3`, no el `python` de Cursor si está en el PATH):

```bash
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
# opcional, horizontes N-paquetes:
pip install -e ".[horizon]"
```

## Estructura

```text
pipeline/           # Paquete instalable (CLI + módulos)
  ui/               # Consola TUI opcional (Textual)
tests/              # Suite pytest (contrato, etiquetado, ML, CLI)
fixtures/           # JSON de ejemplo (PCAPs locales, no versionados)
sample_data/        # CSV auxiliar mínimo para tests
docs/
  ARCHITECTURE.md         # Módulos, flujo y criterios ISO/IEC 25010
  CONTRATO-INTEGRACION.md # Contrato PCAP + JSON upstream
  GUIA-PRUEBAS-ML.md      # Handoff preprocess-ml / validate_ml
scripts/            # setup-venv, pipeline-ui.sh, jupyter-demo.sh, WSL, merge PCAP
notebooks/          # pipeline_demo.ipynb (interfaz Jupyter)
```

Detalle de módulos y calidad: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Dos interfaces (misma lógica, públicos distintos)

| Quién | Cómo quiere verlo | Arranque |
|-------|-------------------|----------|
| Demo / análisis en navegador (tablas, gráficos) | **Jupyter** | `bash scripts/setup-venv.sh --notebook` → `bash scripts/jupyter-demo.sh` |
| Corrida con logs filtrables en terminal | **TUI** | `bash scripts/setup-venv.sh` → `bash scripts/pipeline-ui.sh` |
| Scripts o CI | **CLI** | `python -m pipeline run …` |

Guía corta: [`docs/GUIA-INTERFACES.md`](docs/GUIA-INTERFACES.md).

## Consola interactiva (TUI)

Misma lógica que la CLI, con panel de etapas, logs en vivo y filtros (nivel, búsqueda, solo una etapa), inspirado en el dashboard de logs de local-architecture:

```bash
bash scripts/setup-venv.sh   # incluye extra [ui]
bash scripts/pipeline-ui.sh   # recomendado si `python` del PATH es Cursor
# o:
source .venv/bin/activate
python -m pipeline ui
```

**Problemas habituales (Manjaro + Cursor en el PATH):**

| Síntoma | Qué hacer |
|--------|-----------|
| `externally-managed-environment` al hacer `pip install` | No instalar en el sistema; `bash scripts/setup-venv.sh` |
| `No module named 'pandas'` con `python -m pipeline` | No está en el venv; active o use `.venv/bin/python` |
| El venv existe pero sin paquetes | `bash scripts/setup-venv.sh` recrea el venv si detecta Cursor como intérprete |

Los comandos `run`, `preprocess-ml` y `convert-metadata` siguen disponibles sin Textual.

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

## Cuaderno Jupyter

`notebooks/pipeline_demo.ipynb` ejecuta el pipeline de punta a punta sobre un PCAP + JSON, revisa manifiesto, correlación evento–flujo y razón Parquet/CSV, corre `preprocess-ml` y cierra con una PoC no supervisada acotada. Invoca la CLI con el mismo intérprete del kernel; no reemplaza los módulos ni las pruebas.

```bash
bash scripts/setup-venv.sh --notebook
bash scripts/jupyter-demo.sh
```

Rutas por defecto en la celda de configuración (editables, o vía `PIPELINE_PCAP`, `PIPELINE_METADATA`, `PIPELINE_OUTPUT`). Los PCAP no se versionan: hay que suministrar uno. Con `RUN_PIPELINE = False` reutiliza un `flows.parquet` ya generado.

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

## Licencia y contexto académico

Código liberado bajo MIT (ver `pyproject.toml`). Forma parte del Trabajo de Título citado arriba; la evaluación del producto se documenta en la memoria bajo criterios **ISO/IEC 25010**.
