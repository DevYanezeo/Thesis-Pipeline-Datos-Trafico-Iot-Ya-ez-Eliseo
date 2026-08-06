import pandas as pd

from pipeline.label import LabelingStats, compute_labeling_stats, label_flows
from pipeline.traceability import evaluate_traceability


def _sample_metadata() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "event_id": "e1",
            "event_kind": "attack",
            "source_ip": "10.0.0.1",
            "target_ip": "10.0.0.2",
            "action": "scan",
            "label": "port_scan",
            "duration_s": 10.0,
            "_ts_parsed": pd.Timestamp("2026-01-01T00:00:10Z"),
        },
        {
            "event_id": "e2",
            "event_kind": "benign",
            "source_ip": "10.0.0.3",
            "target_ip": "10.0.0.4",
            "action": "snapshot",
            "label": "take_snapshot",
            "duration_s": 5.0,
            "_ts_parsed": pd.Timestamp("2026-01-01T00:00:20Z"),
        },
    ])


def _sample_flows() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "bidirectional_first_seen_ms": 10_000,
            "bidirectional_last_seen_ms": 15_000,
        },
        {
            "src_ip": "192.168.1.1",
            "dst_ip": "8.8.8.8",
            "bidirectional_first_seen_ms": 50_000,
            "bidirectional_last_seen_ms": 55_000,
        },
    ])


def test_traceability_metrics_structure():
    meta = _sample_metadata()
    flows = label_flows(_sample_flows(), meta)
    stats = compute_labeling_stats(flows)
    metrics = evaluate_traceability(flows, meta, stats)

    assert metrics.total_events == 2
    assert metrics.total_flows == 2
    assert 0 <= metrics.events_with_flow_pct <= 100
    assert metrics.orphan_events_count >= 0
