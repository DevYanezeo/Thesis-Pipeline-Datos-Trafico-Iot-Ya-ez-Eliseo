# Guía de pruebas — Dataset ML (handoff procesado)

**Proyecto:** Pipeline de datos IoT — CyberSecLab DIINF-USACH  
**Autor pipeline:** Eliseo Yañez Robles  
**Versión:** 1.0 — 2026-07-13 (reemplaza el borrador 0.1 "receta")  
**Reunión referencia:** Iturbe 10-jul-2026

---

## 1. Objetivo

El pipeline **produce el dataset ya preprocesado y sin fuga de datos** (data leak), listo
para que el tesista de IDS entrene modelos. La preparación (split, imputación, escalado,
One-Hot, validación anti-fuga) **es responsabilidad del pipeline**, no del consumidor. El
consumidor solo entrena.

> Cambio respecto al borrador 0.1: antes se entregaba un único Parquet y el seminarista
> hacía el split/`fit` (modelo "receta"). Ahora se entrega el paquete **ya procesado y
> validado** (modelo "procesado"), porque la garantía anti-fuga es del productor.

---

## 2. Generar el dataset

### Paso A — Flujos etiquetados (pipeline base)

```bash
python3 -m pipeline run \
  --pcap fixtures/upstream-run-00/capture.pcap \
  --metadata fixtures/upstream-run-00/metadata.json \
  --output output/demo-seminaristas/ \
  --full \
  --privacy pseudonymize \
  --evaluate \
  --verbose
```

Produce `flows.parquet` (con el esquema NFStream completo, ~60 features), `manifest.json`
y `traceability_report.json`.

### Paso B — Preprocesamiento ML (handoff procesado)

```bash
python3 -m pipeline preprocess-ml \
  --input output/demo-seminaristas/flows.parquet \
  --output output/demo-seminaristas/ml/ \
  --test-size 0.2 \
  --split-by episode \
  --stratify \
  --seed 42 \
  --classes three-class \
  --scaler robust \
  --benchmark
```

### Salidas (paquete handoff)

| Archivo | Uso |
|---------|-----|
| `train_processed.parquet` | Train imputado + escalado + One-Hot (fit SOLO aquí) |
| `test_processed.parquet` | Test solo transformado con estadísticas del train |
| `preprocessing_pipeline.joblib` | Transformador ajustado (reutilizable / re-fit en CV) |
| `feature_manifest.json` | Esquema, exclusiones, parámetros de split (trazabilidad) |
| `validation_report.json` | Prueba formal de ausencia de fuga |
| `benchmark_qa.json` | MCC/BACC de QA (con `--benchmark`) |
| `flows.parquet` (Paso A) | Respaldo crudo etiquetado para re-procesar si el modelo lo pide |

---

## 3. Semántica de etiquetas

| `flow_label` | Significado | ¿Usar como target ML? |
|--------------|-------------|------------------------|
| `attack` | Episodio de ataque documentado en JSON | Sí (clase positiva) |
| `benign` | Episodio benigno **artificial** (interacción instrumentada) | Sí (clase legítima instrumentada) |
| `background` | Tráfico doméstico **no documentado** (benigno natural) | Según modo `--classes` |

El ground truth del pipeline es determinista con estas 3 clases (DEC-003). La
interpretación de `background` **no** se decide en el etiquetado sino en el
preprocesamiento, vía `--classes`:

| `--classes` | Efecto |
|-------------|--------|
| `three-class` (default) | Multiclase `attack` / `benign` / `background` |
| `attack-benign` | Excluye `background`; clases `attack` / `benign` |
| `attack-vs-all` | Binario `attack` vs `normal` (= `benign` + `background`) |

**No usar columnas de etiqueta como features de entrada** (el pipeline ya las excluye).

---

## 4. Columnas: esquema de features v1 (congelado)

La lista viva y única está en [`pipeline/dataset_spec.py`](../pipeline/dataset_spec.py)
(`SPEC_VERSION = "1.0"`). El preprocesamiento resuelve las columnas automáticamente:

### Excluidas (identificadores / fuga)

`flow_id`, `event_id`, `id`, `expiration_id`, `src_ip`, `dst_ip`, `src_mac`, `dst_mac`,
`src_oui`, `dst_oui`, `src_port`, `dst_port`, `vlan_id`, `tunnel_id` — más las categóricas
de alta cardinalidad que identifican host/sesión (`requested_server_name`,
`client_fingerprint`, `server_fingerprint`, `user_agent`, `content_type`). Alineado con el
`id_cols` del laboratorio del Prof. Iturbe.

### Excluidas (derivadas de etiqueta / metadatos / tiempo absoluto)

`event_kind`, `event_action`, `mitre_label`, `event_sublabel`, `attack_category`,
`attack_subcategory`, `mitre_ref`, `event_tool`; `scenario_id`, `experiment_id`, `run_id`,
`extraction_mode`, `packet_horizon_n`; timestamps absolutos (`bidirectional_first_seen_ms`,
`bidirectional_last_seen_ms`) — estos últimos se usan para el split temporal, no como feature.

### Features numéricas

Todo el set estadístico NFStream (per-dirección, ps/piat, flags TCP, etc.) que no esté en
las exclusiones. Resolución dinámica sobre el Parquet.

### Categóricas (One-Hot en train)

`protocol`, `ip_version`, `application_name`, `application_category_name`.

---

## 5. Split train / test (dos perillas)

Configurable desde el subcomando; el pipeline lo ejecuta y lo registra en `feature_manifest.json`.

| Perilla | Flag | Default | Impacto |
|---------|------|---------|---------|
| Proporción | `--test-size` | `0.2` (80/20; `0.3`=70/30) | Bajo |
| Unidad | `--split-by` | `episode` | **Alto (anti-fuga)** |

- `episode` (recomendado): agrupa por `event_id`; los flujos de un mismo ataque **no** se
  reparten entre train y test. `background` no pertenece a episodios y se reparte libremente.
  Con `--stratify` se usa `StratifiedGroupKFold` (agrupa + estratifica).
- `temporal`: primeros `(1 - test_size)` por tiempo = train.
- `flow`: aleatorio por flujo. **No recomendado** (reparte episodios → métricas optimistas).

**Regla:** todo `fit` (scaler, One-Hot) es **solo en train**; el test solo se `transform`.
Guardrail: la estratificación protege a `benign` (clase minoritaria).

---

## 6. Preprocesamiento (lo ejecuta el pipeline)

Orden aplicado por [`pipeline/preprocess.py`](../pipeline/preprocess.py):

1. Cargar `flows.parquet`.
2. Resolver clases según `--classes`.
3. Separar features `X` y target `y` (`flow_label`).
4. Split sin fuga (§5).
5. En **train**: `SimpleImputer` + `RobustScaler` (numéricas) y `OneHotEncoder` (categóricas) → `fit_transform`.
6. En **test**: solo `transform` (mismas estadísticas y columnas del train).
7. Emitir el paquete handoff (§2) + validación (§8).
8. Entrenar el modelo IDS: **responsabilidad del tesista de IDS**, fuera de este pipeline.

---

## 7. Anonimización (dos objetivos)

1. **Privacidad** — protección de datos personales (IPs hogar).
2. **Generalización** — el modelo no debe memorizar identidades.

Usar `--privacy pseudonymize` en el Paso A. Los identificadores además se **excluyen** de
las features en el Paso B (§4).

---

## 8. Validación anti-fuga (evidencia para la comisión)

[`pipeline/validate_ml.py`](../pipeline/validate_ml.py) genera `validation_report.json`:

1. Sin solape de grupos train/test (episodios no repartidos).
2. Proporción del split cercana a la solicitada.
3. Distribución de clases preservada entre train y test.
4. Test sin columnas extra respecto a train (detecta re-`fit` accidental en test).
5. Identificadores ausentes de las features.
6. Columna objetivo presente en ambos conjuntos.

Con `--benchmark`, [`pipeline/benchmark_qa.py`](../pipeline/benchmark_qa.py) reporta
**MCC / Balanced-Accuracy / F1-macro / ROC-AUC** de modelos ligeros como control de calidad
de la aprendibilidad del dataset (NO es el IDS; el accuracy simple se omite por engañoso).

---

## 9. Contrato con etapa siguiente (modelos)

| Ítem | Estado |
|------|--------|
| Formato entrada | `train_processed.parquet` + `test_processed.parquet` (features + `flow_label`) |
| Transformador | `preprocessing_pipeline.joblib` (para transformar datos nuevos o re-fit en CV) |
| Garantía anti-fuga | `validation_report.json` con `passed: true` |
| Trazabilidad | `feature_manifest.json` (split, seed, scaler, clases, esquema) |
| Respaldo crudo | `flows.parquet` etiquetado |
| Tests pipeline | `python3 -m pytest tests/ -q` |

---

## 10. Pendientes

- [x] Split configurable 70/30 vs 80/20 (`--test-size`).
- [x] Congelar lista de features v1 (`pipeline/dataset_spec.py`).
- [x] Preprocesamiento sin leak (`python -m pipeline preprocess-ml`).
- [ ] Notebook EDA attack vs benign (responsabilidad del consumidor / entrega demo).
