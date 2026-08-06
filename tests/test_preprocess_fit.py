"""Pruebas del preprocesamiento fit-solo-train (pipeline/preprocess.py)."""
from __future__ import annotations

import pandas as pd
import pytest

from tests.ml_fixtures import make_flows

pytest.importorskip("sklearn")

from pipeline.dataset_spec import ID_COLS, LABEL_COL  # noqa: E402
from pipeline.preprocess import build_preprocessor, preprocess_dataset  # noqa: E402


def test_scaler_fit_only_on_train():
    # train con mediana conocida (=10); test con valores enormes que NO deben influir.
    train = pd.DataFrame({"x": [8.0, 10.0, 12.0]})
    test = pd.DataFrame({"x": [1000.0, 2000.0, 3000.0]})

    ct = build_preprocessor(["x"], [], scaler="robust")
    ct.fit_transform(train)
    ct.transform(test)

    center = ct.named_transformers_["num"].named_steps["scaler"].center_[0]
    assert center == pytest.approx(10.0)  # mediana del TRAIN, no del test


def test_processed_columns_match_and_no_identifier_leak():
    df = make_flows(seed=5)
    result = preprocess_dataset(
        df, test_size=0.2, split_by="episode", stratify=True, seed=42, classes="three-class"
    )

    # Test no introduce columnas extra respecto a train.
    assert set(result.train_processed.columns) == set(result.test_processed.columns)
    assert LABEL_COL in result.train_processed.columns

    # Ninguna feature de salida corresponde a un identificador.
    feature_cols = [c for c in result.train_processed.columns if c != LABEL_COL]
    for col in feature_cols:
        base = col.split("__", 1)[-1]
        assert base not in ID_COLS
        assert not base.startswith("src_ip")
        assert not base.startswith("dst_ip")


def test_manifest_records_parameters():
    df = make_flows(seed=6)
    result = preprocess_dataset(
        df, test_size=0.3, split_by="flow", stratify=True, seed=99, classes="attack-vs-all",
        scaler="standard",
    )
    fm = result.feature_manifest
    assert fm["classes_mode"] == "attack-vs-all"
    assert fm["scaler"] == "standard"
    assert fm["split"]["split_by"] == "flow"
    assert fm["split"]["seed"] == 99
    assert set(fm["class_names"]) == {"attack", "normal"}
