# Arquitectura del pipeline

## Alcance

Producto **downstream**: consume capturas PCAP y metadatos JSON producidos por una capa de orquestación experimental, y entrega un dataset de flujos etiquetados en Apache Parquet (más un paquete opcional listo para ML).

**Fuera de alcance:** orquestación de escenarios, inyección de ataques, captura primaria en el testbed y entrenamiento de IDS.

## Flujo de datos

```
PCAP + events.json
        │
        ▼
   [ingest]  validación de contrato, normalización temporal, event_id
        │
        ▼
  [extract]  NFStream → flujos (fail-hard; único extractor)
        │
        ▼
   [label]   solapamiento temporal + IP → attack | benign | background
        │
        ▼
 [persist]   Parquet (Snappy) + baseline CSV + manifest.json
        │
        ├── [evaluate]      métricas I/O (opcional)
        ├── [traceability]  reporte evento↔flujo
        └── [preprocess-ml] split anti-fuga + fit solo en train (opcional)
```

## Módulos (`pipeline/`)

| Módulo | Responsabilidad |
|--------|-----------------|
| `cli.py` / `__main__.py` | Interfaz de línea de comandos (`run`, `convert-metadata`, `preprocess-ml`) |
| `ingest.py` | Ingesta y validación del par PCAP+JSON |
| `adapters/upstream_metadata_json.py` | Adaptador del contrato JSON upstream |
| `extract.py` | Extracción NFStream (timeouts e `n_dissections` configurables) |
| `early_packets.py` | Horizontes de primeros N paquetes (Scapy; no es extractor) |
| `label.py` | Etiquetado por solapamiento + coincidencia de IP |
| `flow_ids.py` | Identificadores estables de flujo |
| `traceability.py` | Métricas formales de calidad del *ground truth* |
| `persist.py` | Escritura Parquet/CSV y manifiesto |
| `evaluate.py` | Benchmark de almacenamiento y lectura selectiva |
| `privacy.py` | Pseudonimización / anonimización de IP |
| `dataset_spec.py` | Contrato de *features* (exclusión de identificadores) |
| `split.py` | Partición train/test anti-fuga |
| `preprocess.py` | Imputación, escalado, One-Hot (`fit` solo en train) |
| `validate_ml.py` | Invariantes del handoff ML |
| `benchmark_qa.py` | Control de aprendibilidad (no es evaluación de IDS) |

## Calidad (ISO/IEC 25010)

La evaluación del producto se organiza por dimensiones de calidad del estándar ISO/IEC 25010:

| Dimensión | Cómo se verifica en este repo |
|-----------|-------------------------------|
| Corrección funcional | Suite `pytest` + corrida end-to-end sobre fixtures/contrato |
| Eficiencia de desempeño | `--evaluate` (compresión y *speedup* Parquet vs CSV) |
| Fiabilidad | *Fail-fast* sin NFStream / contrato inválido; 70+ tests |
| Usabilidad | CLI documentada; README y guías en `docs/` |
| Seguridad | `--privacy`; exclusión de IDs en `dataset_spec` |
| Mantenibilidad | Paquete instalable (`pyproject.toml`), módulos desacoplados |
| Compatibilidad | PCAP único o multi-segmento; JSON vigente + *legacy* |

## Principios de diseño

1. **Fail-fast:** sin NFStream o con contrato inválido, el proceso aborta con error explícito.
2. **Contrato JSON oficial:** CSV solo auxiliar / *baseline* de I/O.
3. **Tres clases de etiquetado:** `attack` / `benign` / `background` (sin `unknown`).
4. **Anti-fuga en handoff ML:** `fit` exclusivo en train; split preferente por episodio.
