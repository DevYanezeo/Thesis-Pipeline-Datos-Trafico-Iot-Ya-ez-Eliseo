"""Identificadores estables de flujo."""
from __future__ import annotations

import hashlib

import pandas as pd


def assign_flow_ids(flows: pd.DataFrame) -> pd.DataFrame:
    if flows.empty:
        return flows

    df = flows.copy()
    if "id" in df.columns and df["id"].notna().any():
        df["flow_id"] = df["id"].astype(str)
    else:
        df["flow_id"] = [
            _stable_flow_id(row) for _, row in df.iterrows()
        ]
    return df


def _stable_flow_id(row: pd.Series) -> str:
    parts = (
        str(row.get("src_ip", "")),
        str(row.get("dst_ip", "")),
        str(row.get("src_port", "")),
        str(row.get("dst_port", "")),
        str(row.get("protocol", "")),
        str(row.get("bidirectional_first_seen_ms", "")),
    )
    digest = hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]
    return f"flow-{digest}"
