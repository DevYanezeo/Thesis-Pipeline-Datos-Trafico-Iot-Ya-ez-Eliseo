"""Anonimización y pseudonimización de direcciones IP en salida del pipeline."""
from __future__ import annotations

import hashlib
from typing import Literal

import pandas as pd

PrivacyMode = Literal["none", "pseudonymize", "anonymize"]

_IP_COLUMNS = ("src_ip", "dst_ip", "source_ip", "target_ip")


def _pseudonymize_ip(value: str) -> str:
    if not value or pd.isna(value):
        return ""
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]
    return f"psn-{digest}"


def _build_anonymize_map(values: pd.Series) -> dict[str, str]:
    mapping: dict[str, str] = {}
    counter = 1
    for raw in values.dropna().astype(str).unique():
        if not raw:
            continue
        octet2 = (counter // 254) % 256
        octet3 = counter % 254 + 1
        mapping[raw] = f"10.255.{octet2}.{octet3}"
        counter += 1
    return mapping


def apply_privacy(df: pd.DataFrame, mode: PrivacyMode) -> pd.DataFrame:
    """Aplica modo de privacidad a columnas IP conocidas."""
    if mode == "none" or df.empty:
        return df

    out = df.copy()
    present = [c for c in _IP_COLUMNS if c in out.columns]
    if not present:
        return out

    if mode == "pseudonymize":
        for col in present:
            out[col] = out[col].astype(str).map(_pseudonymize_ip)
        return out

    # anonymize: reemplazo consistente dentro del DataFrame
    all_values = pd.concat([out[c] for c in present], ignore_index=True)
    mapping = _build_anonymize_map(all_values)
    for col in present:
        out[col] = out[col].astype(str).map(lambda v: mapping.get(v, v) if v else "")
    return out
