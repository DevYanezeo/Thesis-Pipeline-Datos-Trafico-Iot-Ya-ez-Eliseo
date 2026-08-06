"""Persistencia en CSV baseline y Apache Parquet."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from pipeline import __version__
from pipeline.extract import (
    DEFAULT_ACTIVE_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_N_DISSECTIONS,
)
from pipeline.label import LabelingStats

try:
    import polars as pl
    HAS_POLARS = True
except ImportError:
    HAS_POLARS = False


def write_outputs(
    flows: pd.DataFrame,
    output_dir: str | Path,
    experiment_id: str,
    run_id: str,
    pcap_path: Path,
    metadata_path: Path,
    labeling_stats: LabelingStats | None = None,
    metadata_format: str = "json",
    scenario_id: str = "",
    packet_horizon: int | None = None,
    traceability_metrics: dict[str, Any] | None = None,
    write_manifest: bool = True,
    *,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    extraction_mode = (
        flows["extraction_mode"].iloc[0]
        if not flows.empty and "extraction_mode" in flows.columns
        else ("full_flow" if packet_horizon is None else "first_n_packets")
    )

    if packet_horizon is not None and packet_horizon > 0:
        parquet_path = out / f"flows_n{packet_horizon}.parquet"
        csv_path = out / f"flows_n{packet_horizon}_baseline.csv"
    else:
        parquet_path = out / "flows.parquet"
        csv_path = out / "flows_baseline.csv"

    manifest_path = out / "manifest.json"

    flows.to_csv(csv_path, index=False, quoting=csv.QUOTE_NONNUMERIC)

    if HAS_POLARS:
        pl.from_pandas(flows).write_parquet(parquet_path, compression="snappy")
    else:
        flows.to_parquet(parquet_path, index=False, compression="snappy")

    if write_manifest:
        stats = labeling_stats.to_dict() if labeling_stats else {}
        manifest: dict[str, Any] = {
            "schema_version": "1.1",
            "pipeline_version": __version__,
            "experiment_id": experiment_id,
            "run_id": run_id,
            "scenario_id": scenario_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_pcap": str(pcap_path),
            "source_metadata": str(metadata_path),
            "metadata_format": metadata_format,
            "extraction_mode": extraction_mode,
            "packet_horizon_n": packet_horizon,
            "flow_count": len(flows),
            "labeling_stats": stats,
            "traceability_metrics": traceability_metrics or {},
            "nfstream_timeouts": {
                "idle_timeout_s": idle_timeout,
                "active_timeout_s": active_timeout,
                "n_dissections": n_dissections,
            },
            "outputs": {
                "parquet": parquet_path.name,
                "csv_baseline": csv_path.name,
            },
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "csv": csv_path,
        "parquet": parquet_path,
        "manifest": manifest_path,
    }
