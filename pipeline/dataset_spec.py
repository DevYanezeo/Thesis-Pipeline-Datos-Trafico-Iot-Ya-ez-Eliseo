"""Esquema de dataset ML v1 (contrato anti-fuga).

Congela, en un solo lugar, que columnas del ``flows.parquet`` etiquetado pueden usarse
como features de entrada y cuales quedan prohibidas por riesgo de fuga de datos
(memorizacion de identidad) o por ser derivadas de la etiqueta.

La resolucion de features numericas es DINAMICA: se toma todo lo numerico que no este en
las listas de exclusion. Asi el pipeline tolera el esquema estadistico completo de NFStream
(~60 columnas) sin tener que enumerar cada nombre, y a la vez garantiza que ningun
identificador ni columna-etiqueta se cuele como feature.

Referencia de decisiones: docs/GUIA-PRUEBAS-ML.md (secciones 3-4), docs/INVESTIGACION-PREPROCESSOR-ITURBE.md
(el ``id_cols`` del laboratorio del Prof. Iturbe respalda esta denylist).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import pandas as pd
from pandas.api.types import is_numeric_dtype

if TYPE_CHECKING:
    from collections.abc import Sequence

SPEC_VERSION = "1.0"

#: Columna objetivo del ground truth (3 clases deterministas).
LABEL_COL = "flow_label"

#: Columnas derivadas de la etiqueta: solo sirven como target o trazabilidad, NUNCA como feature.
LABEL_DERIVED_COLS = frozenset({
    "flow_label",
    "event_kind",
    "event_action",
    "mitre_label",
    "event_sublabel",
    "attack_category",
    "attack_subcategory",
    "mitre_ref",
    "event_tool",
})

#: Identificadores: permiten al modelo memorizar identidad -> fuga. Excluidos de X.
#: Alineado con el ``id_cols`` de las variantes *-NFStream del laboratorio (Iturbe).
ID_COLS = frozenset({
    "flow_id",
    "event_id",
    "id",
    "expiration_id",
    "src_ip",
    "dst_ip",
    "src_mac",
    "dst_mac",
    "src_oui",
    "dst_oui",
    "src_port",
    "dst_port",
    "vlan_id",
    "tunnel_id",
})

#: Metadatos de corrida/tiempo absoluto: no son features (y los timestamps absolutos
#: identifican sesion). Los timestamps se usan para el split temporal, pero no como X.
META_COLS = frozenset({
    "scenario_id",
    "experiment_id",
    "run_id",
    "extraction_mode",
    "packet_horizon_n",
    "timestamp_start",
    "timestamp_end",
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
})

#: Categoricas de baja cardinalidad aptas para One-Hot.
CATEGORICAL_COLS = (
    "protocol",
    "ip_version",
    "application_name",
    "application_category_name",
)

#: Categoricas de alta cardinalidad que identifican host/sesion (fingerprints, SNI, UA):
#: excluidas por fuga de identidad, igual que en la denylist del laboratorio.
HIGH_CARDINALITY_EXCLUDE = frozenset({
    "requested_server_name",
    "client_fingerprint",
    "server_fingerprint",
    "user_agent",
    "content_type",
})

#: Columna de agrupacion para el split por episodio (evita repartir un mismo ataque).
GROUP_COL = "event_id"
#: Columna temporal para el split temporal.
TIME_COL = "bidirectional_first_seen_ms"
#: Identificador de flujo (unidad del split aleatorio de diagnostico).
FLOW_ID_COL = "flow_id"

#: Referencia congelada v1 del set estadistico NFStream esperado (documentacion; la
#: resolucion real es dinamica). Sirve para auditar que ``extract.py`` entrega el esquema.
NFSTREAM_NUMERICAL_REFERENCE = (
    "bidirectional_duration_ms", "bidirectional_packets", "bidirectional_bytes",
    "src2dst_duration_ms", "src2dst_packets", "src2dst_bytes",
    "dst2src_duration_ms", "dst2src_packets", "dst2src_bytes",
    "bidirectional_min_ps", "bidirectional_mean_ps", "bidirectional_stddev_ps", "bidirectional_max_ps",
    "src2dst_min_ps", "src2dst_mean_ps", "src2dst_stddev_ps", "src2dst_max_ps",
    "dst2src_min_ps", "dst2src_mean_ps", "dst2src_stddev_ps", "dst2src_max_ps",
    "bidirectional_min_piat_ms", "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms", "bidirectional_max_piat_ms",
    "src2dst_min_piat_ms", "src2dst_mean_piat_ms", "src2dst_stddev_piat_ms", "src2dst_max_piat_ms",
    "dst2src_min_piat_ms", "dst2src_mean_piat_ms", "dst2src_stddev_piat_ms", "dst2src_max_piat_ms",
    "bidirectional_syn_packets", "bidirectional_cwr_packets", "bidirectional_ece_packets",
    "bidirectional_urg_packets", "bidirectional_ack_packets", "bidirectional_psh_packets",
    "bidirectional_rst_packets", "bidirectional_fin_packets",
    "src2dst_syn_packets", "src2dst_ack_packets", "src2dst_psh_packets",
    "src2dst_rst_packets", "src2dst_fin_packets",
    "dst2src_syn_packets", "dst2src_ack_packets", "dst2src_psh_packets",
    "dst2src_rst_packets", "dst2src_fin_packets",
    "application_confidence",
)

#: Modos de problema de clasificacion (decision de PREPROCESAMIENTO, no del etiquetado).
CLASS_MODES = ("three-class", "attack-benign", "attack-vs-all")

#: Columnas que nunca deben aparecer como feature (union de exclusiones no categoricas).
EXCLUDED_FROM_FEATURES = ID_COLS | META_COLS | LABEL_DERIVED_COLS | HIGH_CARDINALITY_EXCLUDE


def resolve_feature_columns(df: pd.DataFrame) -> tuple[list[str], list[str]]:
    """Devuelve (numerical_cols, categorical_cols) presentes en ``df``, sin columnas de fuga.

    - Categoricas: interseccion de ``CATEGORICAL_COLS`` con las columnas del DataFrame.
    - Numericas: toda columna numerica que no este excluida ni sea categorica.
    """
    categorical = [c for c in CATEGORICAL_COLS if c in df.columns]
    categorical_set = set(categorical)
    numerical = [
        c
        for c in df.columns
        if c not in EXCLUDED_FROM_FEATURES
        and c not in categorical_set
        and is_numeric_dtype(df[c])
    ]
    return numerical, categorical


def resolve_target(
    df: pd.DataFrame,
    mode: str = "three-class",
) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Aplica el modo de clases y devuelve (df_filtrado, y, class_names).

    - ``three-class``  : multiclase attack/benign/background (todas las filas).
    - ``attack-benign``: excluye background; clases attack/benign.
    - ``attack-vs-all``: binario attack vs normal (benign+background).
    """
    if LABEL_COL not in df.columns:
        raise ValueError(f"El dataset no tiene la columna objetivo '{LABEL_COL}'")
    if mode not in CLASS_MODES:
        raise ValueError(f"Modo de clases invalido: {mode!r}. Use uno de {CLASS_MODES}")

    labels = df[LABEL_COL].astype(str)

    if mode == "three-class":
        y = labels
        return df, y, sorted(y.unique())

    if mode == "attack-benign":
        mask = labels.isin(["attack", "benign"])
        filtered = df.loc[mask].reset_index(drop=True)
        y = filtered[LABEL_COL].astype(str)
        return filtered, y, sorted(y.unique())

    # attack-vs-all
    y = labels.where(labels == "attack", other="normal")
    return df, y, ["attack", "normal"]


def spec_summary(numerical: Sequence[str], categorical: Sequence[str]) -> dict:
    """Resumen serializable del esquema resuelto (para feature_manifest.json)."""
    return {
        "spec_version": SPEC_VERSION,
        "label_col": LABEL_COL,
        "n_numerical": len(numerical),
        "n_categorical": len(categorical),
        "numerical_cols": list(numerical),
        "categorical_cols": list(categorical),
        "excluded_id_cols": sorted(ID_COLS),
        "excluded_meta_cols": sorted(META_COLS),
        "excluded_label_derived_cols": sorted(LABEL_DERIVED_COLS),
        "excluded_high_cardinality_cols": sorted(HIGH_CARDINALITY_EXCLUDE),
    }
