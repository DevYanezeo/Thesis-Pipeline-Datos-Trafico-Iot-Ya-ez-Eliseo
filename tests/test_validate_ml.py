"""Pruebas del validador anti-fuga (pipeline/validate_ml.py)."""
from __future__ import annotations

import pytest

from tests.ml_fixtures import make_flows

pytest.importorskip("sklearn")

from pipeline.preprocess import preprocess_dataset  # noqa: E402
from pipeline.validate_ml import validate_processed  # noqa: E402


def _clean_result():
    df = make_flows(seed=8)
    return preprocess_dataset(
        df, test_size=0.2, split_by="episode", stratify=True, seed=42, classes="three-class"
    )


def test_clean_dataset_passes():
    result = _clean_result()
    report = validate_processed(result.train_processed, result.test_processed, result.feature_manifest)
    assert report["passed"] is True
    assert report["n_failed"] == 0


def test_extra_test_column_detected():
    result = _clean_result()
    test_df = result.test_processed.copy()
    test_df["columna_fantasma"] = 1.0

    report = validate_processed(result.train_processed, test_df, result.feature_manifest)
    assert report["passed"] is False
    failed = {c["name"] for c in report["checks"] if not c["passed"]}
    assert "no_extra_test_columns" in failed


def test_identifier_feature_detected():
    result = _clean_result()
    train_df = result.train_processed.copy()
    test_df = result.test_processed.copy()
    train_df["src_ip"] = "10.0.0.1"
    test_df["src_ip"] = "10.0.0.2"

    report = validate_processed(train_df, test_df, result.feature_manifest)
    assert report["passed"] is False
    failed = {c["name"] for c in report["checks"] if not c["passed"]}
    assert "no_identifier_features" in failed


def test_group_overlap_detected():
    result = _clean_result()
    manifest = dict(result.feature_manifest)
    manifest["split"] = dict(manifest["split"])
    manifest["split"]["group_overlap"] = 3  # fuga inyectada

    report = validate_processed(result.train_processed, result.test_processed, manifest)
    failed = {c["name"] for c in report["checks"] if not c["passed"]}
    assert "no_group_overlap" in failed
    assert report["passed"] is False
