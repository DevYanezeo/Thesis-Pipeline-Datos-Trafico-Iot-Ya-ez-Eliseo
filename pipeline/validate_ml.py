"""Validacion formal de invariantes ML (prueba anti-fuga).

Verifica sobre los artefactos procesados que el dataset entregado no tiene fuga de datos.
Es la evidencia objetiva para la comision de ML (espeja ``validate_outputs.py`` del
laboratorio del Prof. Iturbe). Emite un reporte serializable ``validation_report.json``.

Chequeos:
    1. Sin solape de grupos train/test (episodios no repartidos).
    2. Proporcion del split cercana a la solicitada.
    3. Distribucion de clases preservada entre train y test.
    4. Test sin columnas extra respecto a train (detecta re-fit del One-Hot/scaler en test).
    5. Identificadores ausentes de las features (denylist anti-fuga respetada).
    6. Columna objetivo presente en ambos conjuntos.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from pipeline.dataset_spec import ID_COLS, LABEL_COL

#: Tolerancias. El split por episodio mueve grupos enteros, por lo que ni la proporcion
#: global ni la distribucion de clases pueden ser exactas (se sacrifica algo de balance a
#: cambio de CERO fuga, que es la garantia prioritaria).
RATIO_ABS_TOL = 0.1
CLASS_DIST_ABS_TOL = 0.15


def _check(name: str, passed: bool, detail: str, *, critical: bool = True) -> dict:
    return {"name": name, "passed": bool(passed), "critical": critical, "detail": detail}


def _feature_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c != LABEL_COL]


def _base_name(feature: str) -> str:
    """Nombre de columna origen a partir del nombre post-ColumnTransformer."""
    for prefix in ("num__", "cat__"):
        if feature.startswith(prefix):
            return feature[len(prefix):]
    return feature


def _leaks_identifier(feature: str) -> bool:
    base = _base_name(feature)
    for idc in ID_COLS:
        if base == idc or base.startswith(f"{idc}_"):
            return True
    return False


def _class_proportions(series: pd.Series) -> dict[str, float]:
    counts = series.astype(str).value_counts(normalize=True)
    return {str(k): float(v) for k, v in counts.items()}


def validate_processed(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    feature_manifest: dict,
) -> dict:
    """Corre los invariantes y devuelve un reporte con ``passed`` global."""
    checks: list[dict] = []

    split_meta = feature_manifest.get("split", {})

    # 1. Solape de grupos (solo aplica al split por episodio).
    if "group_overlap" in split_meta:
        overlap = int(split_meta["group_overlap"])
        checks.append(_check(
            "no_group_overlap",
            overlap == 0,
            f"grupos compartidos train/test: {overlap} (esperado 0)",
        ))
    else:
        checks.append(_check(
            "no_group_overlap",
            True,
            f"split_by='{split_meta.get('split_by')}' no usa grupos; se omite el chequeo",
            critical=False,
        ))

    # 2. Proporcion del split.
    n_train, n_test = len(train_df), len(test_df)
    total = n_train + n_test
    achieved = n_test / total if total else 0.0
    requested = float(split_meta.get("test_size_requested", 0.2))
    checks.append(_check(
        "split_ratio",
        abs(achieved - requested) <= RATIO_ABS_TOL,
        f"test fraccion={achieved:.3f} vs solicitada={requested:.3f} (tol {RATIO_ABS_TOL})",
    ))

    # 3. Distribucion de clases preservada.
    if LABEL_COL in train_df.columns and LABEL_COL in test_df.columns:
        train_prop = _class_proportions(train_df[LABEL_COL])
        test_prop = _class_proportions(test_df[LABEL_COL])
        all_classes = set(train_prop) | set(test_prop)
        max_diff = max(
            (abs(train_prop.get(c, 0.0) - test_prop.get(c, 0.0)) for c in all_classes),
            default=0.0,
        )
        checks.append(_check(
            "class_distribution_preserved",
            max_diff <= CLASS_DIST_ABS_TOL,
            f"max diferencia de proporcion por clase={max_diff:.3f} (tol {CLASS_DIST_ABS_TOL})",
        ))
    else:
        checks.append(_check(
            "class_distribution_preserved",
            False,
            f"falta la columna objetivo '{LABEL_COL}' en train o test",
        ))

    # 4. Test sin columnas extra respecto a train.
    train_cols = set(train_df.columns)
    test_cols = set(test_df.columns)
    extra = sorted(test_cols - train_cols)
    checks.append(_check(
        "no_extra_test_columns",
        len(extra) == 0,
        f"columnas extra en test: {extra or 'ninguna'}",
    ))

    # 5. Identificadores ausentes de las features.
    leaking = sorted(c for c in _feature_columns(train_df) if _leaks_identifier(c))
    checks.append(_check(
        "no_identifier_features",
        len(leaking) == 0,
        f"features que parecen identificadores: {leaking or 'ninguna'}",
    ))

    # 6. Columna objetivo presente.
    checks.append(_check(
        "target_present",
        LABEL_COL in train_df.columns and LABEL_COL in test_df.columns,
        f"columna objetivo '{LABEL_COL}' presente en train y test",
    ))

    passed = all(c["passed"] for c in checks if c["critical"])
    return {
        "passed": passed,
        "n_checks": len(checks),
        "n_failed": sum(1 for c in checks if not c["passed"]),
        "checks": checks,
        "summary": {
            "n_train": n_train,
            "n_test": n_test,
            "achieved_test_fraction": round(achieved, 4),
        },
    }


def write_report(report: dict, output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "validation_report.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path
