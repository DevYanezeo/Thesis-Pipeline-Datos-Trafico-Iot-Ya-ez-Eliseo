# Guía de interfaces — mismo pipeline, dos formas de mirarlo

El **núcleo** es único: `python -m pipeline run | preprocess-ml | convert-metadata`.  
Las interfaces solo cambian **cómo se lanzan los comandos** y **cómo se ven los resultados**.

## ¿Quién usa qué?

| Perfil | Preferencia | Herramienta | Qué obtiene |
|--------|-------------|-------------|-------------|
| Seminarista, docente, demostración | Ver paso a paso en navegador, tablas y gráficos | **Jupyter** — `notebooks/pipeline_demo.ipynb` | Celdas con configuración, salida de corrida, lectura de Parquet, manifiesto, trazabilidad, handoff ML y PoC corta |
| Operador técnico, depuración de corridas | Logs en vivo, filtro por etapa/nivel, búsqueda | **TUI** — `python -m pipeline ui` | Formularios + consola (inspirada en local-architecture) |
| Automatización, CI, scripts | Terminal sin UI | **CLI** | Mismos flags que siempre; salida en stdout |

No hay que elegir una sola: **una persona puede usar Jupyter** para revisar el dataset y **otra la TUI** para monitorear una corrida larga con NFStream.

## Instalación (una sola vez)

```bash
bash scripts/setup-venv.sh --all   # dev + TUI + Jupyter
```

Solo TUI (sin Jupyter):

```bash
bash scripts/setup-venv.sh
```

## Arranque rápido

```bash
# Jupyter — cuaderno guiado
bash scripts/jupyter-demo.sh

# TUI — consola con logs
bash scripts/pipeline-ui.sh
```

Ambos scripts usan `.venv/bin/python` (importante en Manjaro si `python` del PATH apunta a Cursor).

## Jupyter: qué ver y qué editar

- Abrir `notebooks/pipeline_demo.ipynb`.
- Celda de configuración: rutas PCAP/JSON/salida, `RUN_PIPELINE`, timeouts, split.
- Variables de entorno opcionales: `PIPELINE_PCAP`, `PIPELINE_METADATA`, `PIPELINE_OUTPUT`.
- El cuaderno llama la CLI con `subprocess`; no reimplementa ingesta/etiquetado.

## TUI: qué ver

- Menú → formulario → consola en vivo.
- Etapas `[ingest]`, `[extract]`, `[label]`, `[persist]` (y análogas en preprocess).
- Teclas: `l` nivel, `/` buscar, `␣`/`a`/`⏎` por etapa, `?` ayuda.

## Cuándo no usar la interfaz gráfica

- Pipelines en cron, GitHub Actions o WSL sin terminal interactiva → **CLI** directa.
- NFStream en servidor sin pantalla → **CLI**; la TUI no cancela extracción en curso.

## Referencias

- Arquitectura: [`ARCHITECTURE.md`](ARCHITECTURE.md)
- ML handoff: [`GUIA-PRUEBAS-ML.md`](GUIA-PRUEBAS-ML.md)
- README: sección requisitos y problemas de venv en Manjaro