# Contrato de integración — Orquestador upstream ↔ Pipeline downstream

**Proyecto:** CyberSecLab DIINF-USACH  
**Tesis downstream:** Eliseo Yañez Robles — pipeline de datos IoT  
**Tesis upstream:** capa de orquestación experimental  
**Versión borrador:** 1.1 — 2026-07-10  
**Última reunión:** 10-jul-2026 (Iturbe + upstream)

---

## 1. Principio acordado (feedback Dr. Iturbe, 29-jun-2026)

El contrato oficial entre la capa de orquestación y el pipeline downstream es:

> **PCAP + JSON de eventos del orquestador**

El CSV puede existir como **representación auxiliar, temporal o exportable**, pero **no** como fuente primaria de trazabilidad.

---

## 2. Artefactos por corrida experimental

| Artefacto | Productor | Consumidor | Obligatorio |
|-----------|-----------|------------|-------------|
| `capture.pcap` | Testbed / captura upstream | Pipeline (NFStream) | Sí |
| `events.json` | Orquestador | Pipeline (ingesta + etiquetado) | Sí |
| `events.csv` | Derivado (export interno) | Solo benchmark / depuración | No |

---

## 3. Esquema JSON mínimo (`events.json`)

### 3.1 Raíz del documento

| Campo | Tipo | Obligatorio | Descripción |
|-------|------|-------------|-------------|
| `schema_version` | string | Sí | Ej.: `"1.0"` |
| `experiment_id` | string | Sí | Identificador de experimento (ej. `"00"`) |
| `scenario_id` | string | Recomendado | Escenario declarativo ejecutado |
| `started_at` | ISO-8601 UTC | Sí | Inicio de captura (referencia temporal) |
| `finished_at` | ISO-8601 UTC | Opcional | Fin de corrida |
| `planned_duration_s` | number | Opcional | Duración planificada |
| `timezone` | string | Recomendado | Ej.: `"UTC"` |
| `orchestrator_version` | string | Opcional | Versión del orquestador |
| `artifacts` | array | Opcional | Lista de artefactos con hash/path |
| `events` | array | Sí | Eventos benignos y de ataque |

### 3.2 Objeto `events[]`

| Campo | Tipo | Obligatorio | Uso en pipeline |
|-------|------|-------------|-----------------|
| `event_id` | string | **No** (upstream) | Generado en **downstream** en ingesta si falta; obligatorio en **Parquet** de salida |
| `absolute_timestamp` | ISO-8601 UTC | Preferido | Inicio del evento |
| `offset_s` | number | Legacy | Segundos desde `started_at` |
| `scheduled_dt` | string datetime | Aceptado (upstream actual) | Inicio del evento (p. ej. `27/07/2026 17:42:03`); si no hay zona → America/Santiago |
| `duration_s` | number | Sí | `>0` = ventana; `0` = ataque singular o benigno corto (downstream usa 1 s) |
| `event_kind` / `event_type` | string | Sí | `attack` \| `benign` |
| `action` | string | Sí | Ej. `port_scan`, `take_snapshot` |
| `label` | string | Sí | Clase gruesa (`attack`/`benign`) o acción (legacy) |
| `sublabel` | string | Recomendado | Ej. `artificial` = episodio instrumentado |
| `category` / `subcategory` | string | Recomendado | Taxonomía de ataque |
| `mitre_ref` | string | Opcional | Referencia MITRE ATT&CK |
| `tool` | string | Opcional | Herramienta usada |
| `source_ip` / `source` | string | Sí | IP origen |
| `target_ip` / `target` | string | Sí | IP destino |
| `device_id` | string | Opcional | Dispositivo origen en testbed |
| `attack_id` / `action_id` | string | Opcional | ID de vector de ataque |
| `status` | string | Opcional | `completed`, `failed`, etc. |
| `notes` | string | Opcional | Texto libre |

\* Ancla temporal por evento (prioridad en el adapter):
1. ``absolute_timestamp`` UTC (preferido / contrato jul-2026)
2. ``offset_s`` respecto de ``started_at`` (legacy)
3. ``scheduled_dt`` fecha/hora de inicio del evento (formato upstream actual; si no trae zona se asume America/Santiago → UTC)

``duration_s``: si es ``> 0``, ventana extendida (p. ej. flood). Si es ``0``, semántica upstream = **ataque singular o evento benigno corto**; el pipeline aplica ventana mínima de **1 s** para el solape.

### 3.3 Semántica de etiquetas (downstream)

| `flow_label` | Significado |
|--------------|-------------|
| `attack` | Flujo solapa con evento JSON `attack` |
| `benign` | Flujo solapa con evento JSON `benign` (**benigno artificial** — interacción instrumentada) |
| `background` | Sin episodio JSON (**benigno natural** / tráfico doméstico no documentado) |

El JSON **no** declara tráfico de fondo; solo episodios de interés experimental.

### 3.4 Capturas multi-segmento (`artifacts[]` + `_partN`)

En dumps reales el archivo `{run}.pcap` **sin** `_part` suele ser el **primer segmento** de la captura (p. ej. 21:37→23:04), y `*_part1.pcap`, `*_part2.pcap` continúan la línea de tiempo. **No** son un “merge duplicado” de las parts.

| Política | Detalle |
|----------|---------|
| **Qué consumir** | **Todos** los PCAPs listados en `artifacts[]` que existan en disco |
| **Orden** | Primero el segmento sin `_part`, luego `_part1`, `_part2`, … |
| **CLI** | `python -m pipeline run --artifact-pcap-dir <dir> --metadata <json> …` |

Upstream debe listar todos los segmentos de la corrida. Omitir el primer `.pcap` deja fuera la mitad inicial del escenario y produce eventos huérfanos.

### 3.5 Ejemplo real (corrida piloto 00)

Ver fixture: `fixtures/upstream-run-00/metadata.json`

---

## 4. Mapeo JSON → columnas internas del pipeline

| Campo JSON | Columna interna | Notas |
|------------|-----------------|-------|
| `experiment_id` | `experiment_id` | Raíz |
| `started_at` + `offset_s` | `absolute_timestamp` | Legacy: calculado |
| `absolute_timestamp` | `absolute_timestamp` | Preferido (jul-2026) |
| `scheduled_dt` | `absolute_timestamp` | Inicio de evento (upstream actual); zona local → UTC si hace falta |
| `offset_s` | `relative_timestamp_s` | Directo / derivado |
| `event_type` / `event_kind` | `event_kind` | Normalizado |
| `source` / `source_ip` | `source_ip` | |
| `target` / `target_ip` | `target_ip` | |
| `action` | `action` | |
| `label` | `label` | |
| `duration_s` | `duration_s` | `0` = singular/benigno corto → ventana 1 s en etiquetado |
| `event_id` | `event_id` | Generado downstream si falta en JSON |

---

## 5. Salida del pipeline (`output/{experiment_id}-{run_id}/`)

| Archivo | Descripción |
|---------|-------------|
| `flows.parquet` | Flujos NFStream + etiquetas + metadatos de extracción |
| `manifest.json` | Trazabilidad, stats, configuración de corrida |
| `flows_baseline.csv` | Solo benchmark I/O (opcional) |
| `traceability_report.json` | Métricas formales de calidad del ground truth |
| `io_metrics.json` | Benchmark formato + consultas analíticas |

### 5.1 Metadatos Parquet (por flujo)

| Campo | Descripción |
|-------|-------------|
| `flow_id` | ID NFStream |
| `event_id` | Evento JSON asociado (si aplica) |
| `scenario_id` | Escenario experimental |
| `packet_horizon_n` | N paquetes usados (`null` = flujo completo) |
| `extraction_mode` | `full_flow` \| `first_n_packets` |
| `original_flow_packet_count` | Paquetes totales del flujo |
| `used_packet_count` | Paquetes efectivamente usados |
| `flow_label` | `attack` \| `benign` \| `background` |
| `bidirectional_first_seen_ms` | Inicio flujo |
| `bidirectional_last_seen_ms` | Fin flujo |

---

## 6. Parametrización primeros N paquetes (requerimiento Iturbe)

El pipeline aceptará `--packet-horizon N` para generar datasets derivados:

| Modo | `extraction_mode` | Descripción |
|------|-------------------|-------------|
| Flujo completo | `full_flow` | Default |
| Primeros N | `first_n_packets` | Caracterización temprana |

Ejemplos de salida: `flows_full.parquet`, `flows_n10.parquet` (o columna `packet_horizon_n` única).

**Alcance tesis:** diseño e implementación del pipeline; **no** entrenamiento de modelos IDS.

---

## 7. Métricas de trazabilidad (evaluación formal)

| Métrica | Definición |
|---------|------------|
| `events_with_flow_pct` | % eventos JSON con ≥1 flujo asociado |
| `flows_labeled_pct` | % flujos con etiqueta ≠ background |
| `background_pct` | % flujos sin solapamiento con evento |
| `ambiguous_overlap_pct` | % flujos con solapamiento multi-evento |
| `label_conflict_count` | Conflictos attack vs benign sin resolver |
| `orphan_events_count` | Eventos sin ningún flujo asociado |
| `attack_traceability_pct` | % flujos attack con `event_id` coincidente |

---

## 8. Checklist reunión (cerrar contrato)

- [ ] Formato oficial de salida del orquestador: **JSON** (+ PCAP)
- [ ] Campos mínimos del JSON acordados (§3)
- [ ] Identificadores comunes: `experiment_id`, `scenario_id`, `event_id`, `device_id`
- [ ] Timestamps: `started_at`, `offset_s` o `absolute_timestamp`, timezone UTC
- [ ] Relación PCAP ↔ experimento (naming, `artifacts[]`)
- [ ] Representación eventos benignos, ataques y background
- [ ] Eventos simultáneos / solapados: prioridad `attack` > `benign`
- [ ] Campos obligatorios vs opcionales
- [ ] Salida Parquet + manifest del pipeline
- [ ] Parametrización `packet_horizon_n`
- [ ] Documentación en `schema_version`
- [ ] Repositorio destino: organización **CyberSecLab** (migración post-acuerdo)

---

## 9. Notas post-reunión (10-jul-2026)

| Tema | Acuerdo | Responsable | Fecha |
|------|---------|-------------|-------|
| `event_id` | No en JSON upstream; pipeline lo genera | Eliseo (implementado) | 10-jul |
| Timestamps | `absolute_timestamp` obligatorio; deprecar `offset_s` | export upstream | Pendiente |
| Etiquetas | benign artificial (JSON) vs background = benigno natural | Contrato §3.4 | 10-jul |
| Fase ML | Documento pruebas + dataset martes; split 70/30 u 80/20 justificado | Eliseo | Antes martes |
| Anonimización | Privacidad + anti-sesgo; antes de entregar a seminaristas | Eliseo | Antes martes |
| ISO 25010 | Cap. 4 ampliado con atributos calidad software | Eliseo | Tesis |
| Versión pipeline | `pipeline_version` en manifest | Eliseo | En código 1.0.0 |
| Caracterización v1 | Congelar esquema NFStream antes de seminaristas | Eliseo + Iturbe | Martes |

**Guía operativa ML:** `docs/GUIA-PRUEBAS-ML.md`
