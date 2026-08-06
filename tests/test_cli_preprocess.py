"""Pruebas del subcomando CLI preprocess-ml (pipeline/cli.py)."""
from __future__ import annotations

import pytest

from tests.ml_fixtures import make_flows

pytest.importorskip("sklearn")

from pipeline.cli import EXIT_OK, EXIT_USAGE, main  # noqa: E402


def _write_flows(tmp_path, seed=10):
    df = make_flows(seed=seed)
    path = tmp_path / "flows.parquet"
    df.to_parquet(path, index=False)
    return path


def test_preprocess_ml_happy_path(tmp_path):
    flows = _write_flows(tmp_path)
    out = tmp_path / "ml"

    code = main([
        "preprocess-ml",
        "--input", str(flows),
        "--output", str(out),
        "--split-by", "episode",
        "--classes", "attack-benign",
        "--test-size", "0.2",
        "--benchmark",
    ])

    assert code == EXIT_OK
    for name in (
        "train_processed.parquet",
        "test_processed.parquet",
        "preprocessing_pipeline.joblib",
        "feature_manifest.json",
        "validation_report.json",
        "benchmark_qa.json",
    ):
        assert (out / name).exists(), f"falta {name}"


def test_preprocess_ml_missing_input(tmp_path):
    code = main([
        "preprocess-ml",
        "--input", str(tmp_path / "no_existe.parquet"),
        "--output", str(tmp_path / "ml"),
    ])
    assert code == EXIT_USAGE


def test_preprocess_ml_no_benchmark_skips_report(tmp_path):
    flows = _write_flows(tmp_path, seed=11)
    out = tmp_path / "ml2"

    code = main([
        "preprocess-ml",
        "--input", str(flows),
        "--output", str(out),
        "--split-by", "flow",
        "--classes", "three-class",
    ])

    assert code == EXIT_OK
    assert (out / "train_processed.parquet").exists()
    assert not (out / "benchmark_qa.json").exists()
