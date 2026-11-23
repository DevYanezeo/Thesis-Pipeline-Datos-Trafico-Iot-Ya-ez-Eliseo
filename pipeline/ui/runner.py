"""Ejecuta comandos del CLI con logging conectado al buffer de la consola."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pipeline import cli
from pipeline.extract import (
    DEFAULT_ACTIVE_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_N_DISSECTIONS,
)
from pipeline.ui.handler import attach_pipeline_logging, detach_pipeline_logging
from pipeline.ui.logs import LogBuffer


def run_full_pipeline(buffer: LogBuffer, *, verbose: bool = False, **opts: Any) -> int:
    handler, prev = attach_pipeline_logging(buffer, verbose=verbose)
    try:
        return cli.run_pipeline(
            Path(opts["pcap"]) if opts.get("pcap") else None,
            Path(opts["metadata"]),
            Path(opts["output"]),
            bool(opts.get("evaluate")),
            opts.get("packet_horizon"),
            opts.get("packet_horizons"),
            include_full=bool(opts.get("include_full")),
            statistical_analysis=bool(opts.get("statistical_analysis", True)),
            privacy_mode=opts.get("privacy_mode", "none"),
            artifact_pcap_dir=Path(opts["artifact_pcap_dir"]) if opts.get("artifact_pcap_dir") else None,
            idle_timeout=int(opts.get("idle_timeout", DEFAULT_IDLE_TIMEOUT)),
            active_timeout=int(opts.get("active_timeout", DEFAULT_ACTIVE_TIMEOUT)),
            n_dissections=int(opts.get("n_dissections", DEFAULT_N_DISSECTIONS)),
        )
    finally:
        detach_pipeline_logging(handler, prev)


def run_preprocess(buffer: LogBuffer, *, verbose: bool = False, **opts: Any) -> int:
    handler, prev = attach_pipeline_logging(buffer, verbose=verbose)
    try:
        return cli.run_preprocess_ml(
            Path(opts["input"]),
            Path(opts["output"]),
            test_size=float(opts.get("test_size", 0.2)),
            split_by=str(opts.get("split_by", "episode")),
            stratify=bool(opts.get("stratify", True)),
            seed=int(opts.get("seed", 42)),
            classes=str(opts.get("classes", "three-class")),
            scaler=str(opts.get("scaler", "robust")),
            benchmark=bool(opts.get("benchmark")),
        )
    finally:
        detach_pipeline_logging(handler, prev)


def run_convert(buffer: LogBuffer, *, verbose: bool = False, **opts: Any) -> int:
    handler, prev = attach_pipeline_logging(buffer, verbose=verbose)
    try:
        return cli.run_convert_metadata(
            Path(opts["json"]),
            Path(opts["pcap"]),
            Path(opts["output"]),
        )
    finally:
        detach_pipeline_logging(handler, prev)


def list_output_artifacts(output_dir: Path) -> list[str]:
    """Nombres de artefactos conocidos presentes en el directorio de salida."""
    if not output_dir.is_dir():
        return []
    patterns = (
        "manifest.json",
        "traceability_report.json",
        "flows.parquet",
        "flows_baseline.csv",
        "train_processed.parquet",
        "test_processed.parquet",
        "preprocessing_pipeline.joblib",
        "feature_manifest.json",
        "validation_report.json",
        "benchmark_qa.json",
    )
    found: list[str] = []
    for name in sorted(output_dir.iterdir(), key=lambda p: p.name):
        if not name.is_file():
            continue
        n = name.name
        if n in patterns or n.startswith("flows_n") or n.startswith("io_metrics"):
            found.append(n)
    return found