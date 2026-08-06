"""Validación y lectura de artefactos de entrada (PCAP + metadatos JSON o CSV)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from pipeline.adapters.upstream_metadata_json import json_to_events_dataframe

REQUIRED_METADATA_COLUMNS = [
    "absolute_timestamp",
    "event_kind",
    "source_ip",
    "target_ip",
    "action",
    "label",
]


@dataclass
class IngestResult:
    pcap_path: Path
    metadata: pd.DataFrame
    experiment_id: str
    run_id: str
    capture_started_at: datetime | None = None
    metadata_format: str = "json"
    scenario_id: str = ""


def _parse_timestamp(value: str) -> datetime:
    value = value.strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise ValueError(f"No se pudo parsear timestamp: {value!r}")


def _finalize_metadata_df(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        raise ValueError("Archivo de metadatos vacío")

    missing = [c for c in REQUIRED_METADATA_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Columnas faltantes en metadatos: {missing}")

    df = df.copy()
    df["_ts_parsed"] = df["absolute_timestamp"].astype(str).map(_parse_timestamp)
    if "duration_s" not in df.columns:
        df["duration_s"] = 0.0
    df["duration_s"] = pd.to_numeric(df["duration_s"], errors="coerce").fillna(0.0)
    if "event_id" not in df.columns:
        df["event_id"] = [f"evt-{i}" for i in range(1, len(df) + 1)]
    if "scenario_id" not in df.columns:
        df["scenario_id"] = ""
    return df


def _read_metadata_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(
        path,
        comment="#",
        encoding="utf-8",
        dtype={"experiment_id": str, "run_id": str, "event_id": str, "scenario_id": str},
    )
    return _finalize_metadata_df(df)


def _read_metadata_json(path: Path, pcap_path: Path) -> pd.DataFrame:
    payload = json.loads(path.read_text(encoding="utf-8"))
    df = json_to_events_dataframe(payload, pcap_path)
    return _finalize_metadata_df(df)


def ingest(pcap_path: str | Path, metadata_path: str | Path) -> IngestResult:
    pcap = Path(pcap_path)
    meta = Path(metadata_path)

    if not pcap.exists():
        raise FileNotFoundError(f"PCAP no encontrado: {pcap}")
    if not meta.exists():
        raise FileNotFoundError(f"Metadatos no encontrados: {meta}")
    if pcap.stat().st_size == 0:
        raise ValueError(f"PCAP vacío: {pcap}")

    suffix = meta.suffix.lower()
    if suffix == ".json":
        df = _read_metadata_json(meta, pcap)
        metadata_format = "json"
    elif suffix == ".csv":
        df = _read_metadata_csv(meta)
        metadata_format = "csv"
    else:
        raise ValueError(
            f"Formato de metadatos no soportado: {suffix}. Use .json (contrato oficial) o .csv (auxiliar)."
        )

    experiment_id = str(df["experiment_id"].iloc[0]) if "experiment_id" in df.columns else pcap.stem
    run_id = str(df["run_id"].iloc[0]) if "run_id" in df.columns else "run01"
    scenario_id = str(df["scenario_id"].iloc[0]) if "scenario_id" in df.columns and df["scenario_id"].iloc[0] else ""
    if not scenario_id:
        scenario_id = experiment_id

    capture_started_at: datetime | None = None
    if "relative_timestamp_s" in df.columns and not df.empty:
        rel0 = float(df["relative_timestamp_s"].iloc[0])
        capture_started_at = df["_ts_parsed"].iloc[0] - timedelta(seconds=rel0)

    return IngestResult(
        pcap_path=pcap,
        metadata=df,
        experiment_id=experiment_id,
        run_id=run_id,
        capture_started_at=capture_started_at,
        metadata_format=metadata_format,
        scenario_id=scenario_id,
    )
