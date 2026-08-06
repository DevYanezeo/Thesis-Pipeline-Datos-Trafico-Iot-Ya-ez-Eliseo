"""Métricas de tamaño en disco, lectura y consultas analíticas CSV vs Parquet."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import pandas as pd

try:
    import polars as pl
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False

BENCHMARK_COLUMNS = [
    "src_ip",
    "dst_ip",
    "flow_label",
    "bidirectional_bytes",
    "event_id",
    "scenario_id",
    "protocol",
    "application_name",
]


def _build_analytical_queries(sample: pd.DataFrame) -> list[dict[str, Any]]:
    queries: list[dict[str, Any]] = [
        {
            "name": "filter_attack_flows",
            "description": "Flujos con flow_label = attack",
            "filter": lambda df: df[df["flow_label"] == "attack"] if "flow_label" in df.columns else df.iloc[0:0],
        },
        {
            "name": "filter_benign_flows",
            "description": "Flujos con flow_label = benign",
            "filter": lambda df: df[df["flow_label"] == "benign"] if "flow_label" in df.columns else df.iloc[0:0],
        },
        {
            "name": "filter_labeled_flows",
            "description": "Flujos con event_id asignado (trazabilidad)",
            "filter": lambda df: df[df["event_id"].astype(str) != ""] if "event_id" in df.columns else df.iloc[0:0],
        },
    ]

    if "scenario_id" in sample.columns and sample["scenario_id"].astype(str).str.len().gt(0).any():
        sid = str(sample["scenario_id"].astype(str).replace("", pd.NA).dropna().iloc[0])
        queries.append({
            "name": "filter_by_scenario",
            "description": f"Flujos del escenario {sid}",
            "filter": lambda df, s=sid: df[df["scenario_id"].astype(str) == s] if "scenario_id" in df.columns else df.iloc[0:0],
        })

    proto_col = "application_name" if "application_name" in sample.columns else (
        "protocol" if "protocol" in sample.columns else None
    )
    if proto_col and not sample[proto_col].dropna().empty:
        top_proto = str(sample[proto_col].dropna().mode().iloc[0])
        queries.append({
            "name": "filter_by_protocol",
            "description": f"Flujos con {proto_col} = {top_proto}",
            "filter": lambda df, c=proto_col, p=top_proto: df[df[c].astype(str) == p] if c in df.columns else df.iloc[0:0],
        })

    if "bidirectional_first_seen_ms" in sample.columns and not sample.empty:
        median_ms = float(pd.to_numeric(sample["bidirectional_first_seen_ms"], errors="coerce").median())
        queries.append({
            "name": "filter_temporal_window",
            "description": "Flujos con inicio >= mediana temporal del dataset",
            "filter": lambda df, m=median_ms: df[
                pd.to_numeric(df["bidirectional_first_seen_ms"], errors="coerce") >= m
            ] if "bidirectional_first_seen_ms" in df.columns else df.iloc[0:0],
        })

    if "extraction_mode" in sample.columns:
        queries.append({
            "name": "filter_early_horizon",
            "description": "Flujos en modo first_n_packets",
            "filter": lambda df: df[df["extraction_mode"] == "first_n_packets"] if "extraction_mode" in df.columns else df.iloc[0:0],
        })

    if "bidirectional_bytes" in sample.columns and not sample.empty:
        queries.append({
            "name": "high_volume_flows",
            "description": "Flujos con bidirectional_bytes > mediana",
            "filter": lambda df: df[
                pd.to_numeric(df["bidirectional_bytes"], errors="coerce")
                > pd.to_numeric(df["bidirectional_bytes"], errors="coerce").median()
            ] if "bidirectional_bytes" in df.columns and not df.empty else df.iloc[0:0],
        })

    return queries


@dataclass
class IoMetrics:
    csv_size_mb: float
    parquet_size_mb: float
    compression_ratio: float
    csv_read_seconds: float
    parquet_read_seconds: float
    read_speedup: float
    benchmark_columns: list[str]
    analytical_queries: list[dict[str, Any]] = field(default_factory=list)


def _file_size_mb(path: Path) -> float:
    return path.stat().st_size / (1024 * 1024)


def _read_csv_df(path: Path, columns: list[str] | None = None) -> pd.DataFrame:
    try:
        if columns:
            header = pd.read_csv(path, nrows=0).columns.tolist()
            usecols = [c for c in columns if c in header]
            return pd.read_csv(path, usecols=usecols or None)
        return pd.read_csv(path, low_memory=False)
    except (IndexError, pd.errors.ParserError):
        if columns:
            header = pd.read_csv(path, nrows=0).columns.tolist()
            usecols = [c for c in columns if c in header]
            return pd.read_csv(path, usecols=usecols or None, engine="python")
        return pd.read_csv(path, engine="python")


def _read_parquet_df(path: Path, columns: list[str] | None = None) -> pd.DataFrame:
    if HAS_POLARS:
        lf = pl.scan_parquet(path)
        if columns:
            existing = [c for c in columns if c in lf.collect_schema().names()]
            if existing:
                lf = lf.select(existing)
        return lf.collect().to_pandas()
    if columns:
        schema_cols = pd.read_parquet(path, engine="pyarrow").columns.tolist()
        usecols = [c for c in columns if c in schema_cols]
        return pd.read_parquet(path, columns=usecols or None)
    return pd.read_parquet(path)


def _read_csv_seconds(path: Path, columns: list[str] | None = None) -> float:
    start = time.perf_counter()
    _read_csv_df(path, columns)
    return time.perf_counter() - start


def _read_parquet_seconds(path: Path, columns: list[str] | None = None) -> float:
    start = time.perf_counter()
    _read_parquet_df(path, columns)
    return time.perf_counter() - start


def _run_analytical_queries(
    csv_path: Path,
    parquet_path: Path,
    queries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for spec in queries:
        filt: Callable = spec["filter"]
        t0 = time.perf_counter()
        csv_df = _read_csv_df(csv_path)
        csv_filtered = filt(csv_df)
        csv_t = time.perf_counter() - t0

        t0 = time.perf_counter()
        pq_df = _read_parquet_df(parquet_path)
        pq_filtered = filt(pq_df)
        pq_t = time.perf_counter() - t0

        speedup = round(csv_t / pq_t, 2) if pq_t > 0 else 0.0
        results.append({
            "name": spec["name"],
            "description": spec["description"],
            "csv_seconds": round(csv_t, 4),
            "parquet_seconds": round(pq_t, 4),
            "speedup": speedup,
            "result_rows": int(len(pq_filtered)),
        })
    return results


def evaluate_io(csv_path: Path, parquet_path: Path) -> IoMetrics:
    csv_mb = _file_size_mb(csv_path)
    pq_mb = _file_size_mb(parquet_path)
    ratio = csv_mb / pq_mb if pq_mb > 0 else 0.0

    sample = _read_parquet_df(parquet_path)
    header = sample.columns.tolist()
    query_cols = [c for c in BENCHMARK_COLUMNS if c in header]

    csv_t = _read_csv_seconds(csv_path, query_cols)
    pq_t = _read_parquet_seconds(parquet_path, query_cols)
    speedup = csv_t / pq_t if pq_t > 0 else 0.0

    queries = _build_analytical_queries(sample)
    analytical = _run_analytical_queries(csv_path, parquet_path, queries)

    return IoMetrics(
        csv_size_mb=round(csv_mb, 4),
        parquet_size_mb=round(pq_mb, 4),
        compression_ratio=round(ratio, 2),
        csv_read_seconds=round(csv_t, 4),
        parquet_read_seconds=round(pq_t, 4),
        read_speedup=round(speedup, 2),
        benchmark_columns=query_cols,
        analytical_queries=analytical,
    )


def metrics_to_dict(metrics: IoMetrics) -> dict:
    return asdict(metrics)
