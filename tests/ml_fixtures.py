"""Fixtures sinteticas para las pruebas de preprocesamiento ML.

Genera un DataFrame con la forma de ``flows.parquet`` etiquetado: identificadores,
categoricas, timestamps y un set de features numericas tipo NFStream con senal separable
por clase (para que el benchmark de QA sea capaz de aprender algo).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

_NUMERIC_FEATURES = (
    "bidirectional_packets",
    "bidirectional_bytes",
    "bidirectional_duration_ms",
    "src2dst_bytes",
    "dst2src_bytes",
    "bidirectional_mean_ps",
    "bidirectional_stddev_piat_ms",
    "bidirectional_syn_packets",
)

# Centro de la senal por clase (separables para que MCC > 0 en el benchmark).
_CLASS_CENTER = {"attack": 8.0, "benign": 4.0, "background": 1.0}


def _numeric_row(rng: np.random.Generator, center: float) -> dict:
    return {feat: float(rng.normal(center, 0.6)) for feat in _NUMERIC_FEATURES}


def make_flows(
    *,
    seed: int = 0,
    n_attack_ep: int = 12,
    n_benign_ep: int = 12,
    flows_per_ep: int = 4,
    n_background: int = 120,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    ts = 1_700_000_000_000  # epoch ms base
    fid = 0

    def base(label: str, event_id: str) -> dict:
        nonlocal fid, ts
        fid += 1
        ts += 1000
        row = {
            "flow_id": f"flow-{fid:05d}",
            "id": fid,
            "event_id": event_id,
            "flow_label": label,
            "src_ip": f"10.0.0.{rng.integers(1, 250)}",
            "dst_ip": f"10.0.1.{rng.integers(1, 250)}",
            "src_port": int(rng.integers(1024, 65535)),
            "dst_port": int(rng.choice([80, 443, 22, 8080])),
            "protocol": int(rng.choice([6, 17])),
            "ip_version": 4,
            "application_name": str(rng.choice(["HTTP", "TLS", "SSH", "DNS"])),
            "bidirectional_first_seen_ms": ts,
            "bidirectional_last_seen_ms": ts + int(rng.integers(1, 5000)),
        }
        row.update(_numeric_row(rng, _CLASS_CENTER[label]))
        return row

    for ep in range(n_attack_ep):
        for _ in range(flows_per_ep):
            rows.append(base("attack", f"atk-{ep:03d}"))
    for ep in range(n_benign_ep):
        for _ in range(flows_per_ep):
            rows.append(base("benign", f"ben-{ep:03d}"))
    for _ in range(n_background):
        rows.append(base("background", ""))

    df = pd.DataFrame(rows)
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
