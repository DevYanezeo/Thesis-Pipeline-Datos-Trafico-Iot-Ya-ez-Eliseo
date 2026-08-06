"""Etiquetado por solapamiento temporal entre eventos y flujos.

Politica de etiquetado (acta reunion 10-jul-2026, DEC-003):
El ground truth del pipeline es DETERMINISTA y usa exactamente 3 clases objetivas:

    - ``attack``     : ataque artificial (evento JSON ``attack`` + solape temporal + match IP).
    - ``benign``     : benigno artificial (evento JSON ``benign`` instrumentado, idem).
    - ``background`` : benigno natural / trafico no documentado en el JSON (sin solape con evento).

No existe una cuarta clase ``unknown``: un flujo sin correspondencia con ningun evento
es ``background`` por definicion (el JSON documenta episodios, no el trafico de fondo).
Cerrar ``unknown`` aqui mantiene el ground truth puro; la interpretacion "forzada vs
permisiva" de ``background`` (contarlo como normal o excluirlo) es una decision de
PREPROCESAMIENTO downstream (``python -m pipeline preprocess-ml``, flag ``--classes``), no
del etiquetado, para no contaminar el ground truth.

Prioridad ante solapes multiples: ``attack`` > ``benign`` (bitacora 4.2 / checklist punto 8).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pandas as pd


@dataclass
class LabelingStats:
    total_flows: int
    labeled_flows: int
    attack_flows: int
    benign_flows: int
    background_flows: int

    def to_dict(self) -> dict[str, int]:
        return {
            "total_flows": self.total_flows,
            "labeled_flows": self.labeled_flows,
            "attack_flows": self.attack_flows,
            "benign_flows": self.benign_flows,
            "background_flows": self.background_flows,
        }


def _to_epoch_ms(value) -> int | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp() * 1000)
    return None


def _flow_window_ms(row: pd.Series) -> tuple[int | None, int | None]:
    start = _to_epoch_ms(row.get("bidirectional_first_seen_ms"))
    end = _to_epoch_ms(row.get("bidirectional_last_seen_ms"))
    if end is None:
        end = start
    return start, end


def _event_window(event: pd.Series) -> tuple[datetime, datetime]:
    start: datetime = event["_ts_parsed"]
    # duration_s=0 (upstream): ataque singular o benigno corto → ventana mínima 1 s.
    duration_s = float(event.get("duration_s", 0.0) or 0.0)
    if duration_s <= 0:
        duration_s = 1.0
    end = start + timedelta(seconds=duration_s)
    return start, end


def _overlaps(flow_start_ms: int, flow_end_ms: int, ev_start: datetime, ev_end: datetime) -> bool:
    ev_start_ms = int(ev_start.timestamp() * 1000)
    ev_end_ms = int(ev_end.timestamp() * 1000)
    return flow_start_ms <= ev_end_ms and flow_end_ms >= ev_start_ms


def _ip_matches(flow_row: pd.Series, event: pd.Series) -> bool:
    src = str(flow_row.get("src_ip", ""))
    dst = str(flow_row.get("dst_ip", ""))
    targets = {str(event.get("source_ip", "")), str(event.get("target_ip", ""))}
    targets.discard("")
    if not targets:
        return True
    return src in targets or dst in targets


def compute_labeling_stats(flows: pd.DataFrame) -> LabelingStats:
    total = len(flows)
    if total == 0 or "flow_label" not in flows.columns:
        return LabelingStats(0, 0, 0, 0, 0)

    attack = int((flows["flow_label"] == "attack").sum())
    benign = int((flows["flow_label"] == "benign").sum())
    labeled = attack + benign
    background = total - labeled
    return LabelingStats(total, labeled, attack, benign, background)


def _align_relative_flow_timestamps(
    flows: pd.DataFrame,
    capture_started_at: datetime | None,
) -> pd.DataFrame:
    """Convierte ms relativos de captura a epoch ms si NFStream no usa epoch absoluto."""
    if flows.empty or capture_started_at is None:
        return flows
    if "bidirectional_first_seen_ms" not in flows.columns:
        return flows

    first_vals = pd.to_numeric(flows["bidirectional_first_seen_ms"], errors="coerce").dropna()
    if first_vals.empty or first_vals.max() >= 1_000_000_000_000:
        return flows

    anchor_ms = int(capture_started_at.timestamp() * 1000)
    min_rel = int(first_vals.min())
    df = flows.copy()
    df["bidirectional_first_seen_ms"] = (
        pd.to_numeric(df["bidirectional_first_seen_ms"], errors="coerce") - min_rel + anchor_ms
    )
    df["bidirectional_last_seen_ms"] = (
        pd.to_numeric(df["bidirectional_last_seen_ms"], errors="coerce") - min_rel + anchor_ms
    )
    return df


def _apply_event_to_flow(df: pd.DataFrame, idx, chosen: pd.Series, kind: str) -> None:
    action = str(chosen.get("action", ""))
    upstream_label = str(chosen.get("label", ""))
    # Esquema legacy: label = nombre de acción (port_scan). esquema upstream jul-2026: label = attack/benign.
    mitre_label = action if upstream_label in ("attack", "benign") else upstream_label or action

    df.at[idx, "flow_label"] = "attack" if kind == "attack" else "benign"
    df.at[idx, "event_kind"] = kind
    df.at[idx, "event_action"] = action
    df.at[idx, "mitre_label"] = mitre_label
    df.at[idx, "event_id"] = str(chosen.get("event_id", ""))
    df.at[idx, "event_sublabel"] = str(chosen.get("sublabel", ""))
    df.at[idx, "attack_category"] = str(chosen.get("category", ""))
    df.at[idx, "attack_subcategory"] = str(chosen.get("subcategory", ""))
    df.at[idx, "mitre_ref"] = str(chosen.get("mitre_ref", ""))
    df.at[idx, "event_tool"] = str(chosen.get("tool", ""))


def label_flows(
    flows: pd.DataFrame,
    metadata: pd.DataFrame,
    capture_started_at: datetime | None = None,
) -> pd.DataFrame:
    if flows.empty:
        return flows

    df = _align_relative_flow_timestamps(flows, capture_started_at)
    df["flow_label"] = "background"
    df["event_action"] = ""
    df["event_kind"] = ""
    df["mitre_label"] = ""
    df["event_id"] = ""
    df["event_sublabel"] = ""
    df["attack_category"] = ""
    df["attack_subcategory"] = ""
    df["mitre_ref"] = ""
    df["event_tool"] = ""

    events = metadata[metadata["event_kind"].isin(["attack", "benign"])].copy()
    if events.empty:
        return df

    for idx, flow in df.iterrows():
        f_start, f_end = _flow_window_ms(flow)
        if f_start is None or f_end is None:
            continue

        matched_attack = None
        matched_benign = None

        for _, event in events.iterrows():
            ev_start, ev_end = _event_window(event)
            if not _overlaps(f_start, f_end, ev_start, ev_end):
                continue
            if not _ip_matches(flow, event):
                continue

            kind = str(event.get("event_kind", ""))
            if kind == "attack":
                matched_attack = event
                break
            if kind == "benign" and matched_benign is None:
                matched_benign = event

        chosen = matched_attack if matched_attack is not None else matched_benign
        if chosen is None:
            continue

        kind = str(chosen.get("event_kind", "benign"))
        _apply_event_to_flow(df, idx, chosen, kind)

    return df
