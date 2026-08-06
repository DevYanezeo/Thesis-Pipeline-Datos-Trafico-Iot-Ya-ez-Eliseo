"""Benchmark de control de calidad (QA) del dataset.

IMPORTANTE: esto NO es el IDS ni una contribucion de modelado. Es un control de calidad
que responde una sola pregunta: "el dataset entregado es aprendible?". Se entrenan modelos
ligeros sobre el train procesado y se reportan metricas ROBUSTAS al desbalance
(MCC, Balanced-Accuracy, F1-macro, ROC-AUC), tal como exige el taller del Prof. Iturbe;
el accuracy simple se omite adrede por enganoso en clases desbalanceadas.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    balanced_accuracy_score,
    f1_score,
    matthews_corrcoef,
    roc_auc_score,
)

from pipeline.dataset_spec import LABEL_COL


def _split_xy(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    x = df.drop(columns=[c for c in (LABEL_COL,) if c in df.columns])
    y = df[LABEL_COL].astype(str)
    return x, y


def _roc_auc(y_test, proba, classes) -> float | None:
    try:
        if len(classes) == 2:
            pos = classes[-1]
            y_bin = (np.asarray(y_test) == pos).astype(int)
            return float(roc_auc_score(y_bin, proba[:, list(classes).index(pos)]))
        return float(
            roc_auc_score(
                y_test,
                proba,
                multi_class="ovr",
                average="macro",
                labels=list(classes),
            )
        )
    except (ValueError, IndexError):
        return None


def _evaluate_model(model, x_train, y_train, x_test, y_test) -> dict:
    model.fit(x_train, y_train)
    y_pred = model.predict(x_test)

    metrics = {
        "mcc": float(matthews_corrcoef(y_test, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "roc_auc": None,
    }
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(x_test)
        metrics["roc_auc"] = _roc_auc(y_test, proba, list(model.classes_))
    return metrics


def benchmark_qa(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    *,
    seed: int = 42,
) -> dict:
    """Entrena modelos ligeros y devuelve metricas robustas por modelo."""
    x_train, y_train = _split_xy(train_df)
    x_test, y_test = _split_xy(test_df)

    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=100,
            random_state=seed,
            class_weight="balanced",
            n_jobs=-1,
        ),
        "logistic_regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=seed,
        ),
    }

    results: dict[str, dict] = {}
    for name, model in models.items():
        try:
            results[name] = _evaluate_model(model, x_train, y_train, x_test, y_test)
        except Exception as exc:  # noqa: BLE001 - QA no debe romper el pipeline
            results[name] = {"error": str(exc)}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "Control de calidad del dataset (aprendibilidad), no un IDS.",
        "seed": seed,
        "n_train": int(len(train_df)),
        "n_test": int(len(test_df)),
        "classes": sorted(y_train.unique().tolist()),
        "metrics": {
            "reported": ["mcc", "balanced_accuracy", "f1_macro", "roc_auc"],
            "omitted": ["accuracy"],
            "omitted_reason": "accuracy es enganoso en datasets desbalanceados",
        },
        "models": results,
    }


def write_report(report: dict, output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "benchmark_qa.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path
