"""Métricas formales de calidad del ground truth evento-flujo."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any

import pandas as pd

from pipeline.label import LabelingStats, _ip_matches, _overlaps


@dataclass
class TraceabilityMetrics:
    total_events: int
    total_flows: int
    events_with_flow_pct: float
    flows_labeled_pct: float
    background_pct: float
    attack_traceability_pct: float
    orphan_events_count: int
    ambiguous_overlap_count: int
    ambiguous_overlap_pct: float
    label_conflict_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _event_window(event: pd.Series) -> tuple:
    start = event["_ts_parsed"]
    duration_s = float(event.get("duration_s", 0.0) or 0.0)
    if duration_s <= 0:
        duration_s = 1.0
    end = start + timedelta(seconds=duration_s)
    return start, end


def _matching_events_for_flow(flow: pd.Series, events: pd.DataFrame) -> list[pd.Series]:
    f_start = flow.get("bidirectional_first_seen_ms")
    f_end = flow.get("bidirectional_last_seen_ms", f_start)
    if f_start is None or pd.isna(f_start):
        return []

    matched: list[pd.Series] = []
    f_start_i = int(f_start)
    f_end_i = int(f_end) if f_end is not None and not pd.isna(f_end) else f_start_i

    for _, event in events.iterrows():
        ev_start, ev_end = _event_window(event)
        if not _overlaps(f_start_i, f_end_i, ev_start, ev_end):
            continue
        if not _ip_matches(flow, event):
            continue
        matched.append(event)
    return matched


def _count_ambiguous_and_conflicts(flows: pd.DataFrame, metadata: pd.DataFrame) -> tuple[int, int]:
    events = metadata[metadata["event_kind"].isin(["attack", "benign"])].copy()
    if flows.empty or events.empty:
        return 0, 0

    ambiguous = 0
    conflicts = 0
    for _, flow in flows.iterrows():
        matched = _matching_events_for_flow(flow, events)
        if len(matched) > 1:
            ambiguous += 1
            kinds = {str(m.get("event_kind", "")) for m in matched}
            labels = {str(m.get("label", "")) for m in matched}
            if len(kinds) > 1 or len(labels) > 1:
                conflicts += 1
    return ambiguous, conflicts


def _orphan_events(flows: pd.DataFrame, metadata: pd.DataFrame) -> int:
    events = metadata[metadata["event_kind"].isin(["attack", "benign"])].copy()
    if events.empty:
        return 0
    if "event_id" not in flows.columns:
        return len(events)

    labeled = flows[flows["flow_label"].isin(["attack", "benign"])]
    matched_ids = set(labeled["event_id"].astype(str).tolist()) if not labeled.empty else set()
    matched_ids.discard("")

    orphan = 0
    for _, event in events.iterrows():
        eid = str(event.get("event_id", ""))
        if eid and eid not in matched_ids:
            orphan += 1
    return orphan


def evaluate_traceability(
    flows: pd.DataFrame,
    metadata: pd.DataFrame,
    labeling_stats: LabelingStats,
) -> TraceabilityMetrics:
    events = metadata[metadata["event_kind"].isin(["attack", "benign"])]
    total_events = len(events)
    total_flows = labeling_stats.total_flows

    events_with_flow = 0
    if total_events > 0 and "event_id" in flows.columns:
        labeled = flows[flows["flow_label"].isin(["attack", "benign"])]
        matched_event_ids = set(labeled["event_id"].astype(str).tolist()) if not labeled.empty else set()
        matched_event_ids.discard("")
        for _, event in events.iterrows():
            eid = str(event.get("event_id", ""))
            if eid in matched_event_ids:
                events_with_flow += 1

    events_with_flow_pct = round(100.0 * events_with_flow / total_events, 2) if total_events else 0.0
    flows_labeled_pct = round(100.0 * labeling_stats.labeled_flows / total_flows, 2) if total_flows else 0.0
    background_pct = round(100.0 * labeling_stats.background_flows / total_flows, 2) if total_flows else 0.0

    attack_flows = flows[flows["flow_label"] == "attack"] if "flow_label" in flows.columns else pd.DataFrame()
    attack_with_event = 0
    if not attack_flows.empty and "event_id" in attack_flows.columns:
        attack_with_event = int((attack_flows["event_id"].astype(str) != "").sum())
    attack_traceability_pct = (
        round(100.0 * attack_with_event / len(attack_flows), 2) if len(attack_flows) else 0.0
    )

    ambiguous, conflicts = _count_ambiguous_and_conflicts(flows, metadata)
    ambiguous_pct = round(100.0 * ambiguous / total_flows, 4) if total_flows else 0.0

    return TraceabilityMetrics(
        total_events=total_events,
        total_flows=total_flows,
        events_with_flow_pct=events_with_flow_pct,
        flows_labeled_pct=flows_labeled_pct,
        background_pct=background_pct,
        attack_traceability_pct=attack_traceability_pct,
        orphan_events_count=_orphan_events(flows, metadata),
        ambiguous_overlap_count=ambiguous,
        ambiguous_overlap_pct=ambiguous_pct,
        label_conflict_count=conflicts,
    )
