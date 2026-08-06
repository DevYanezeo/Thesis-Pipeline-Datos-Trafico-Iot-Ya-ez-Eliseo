from datetime import datetime, timedelta, timezone

import pandas as pd

from pipeline.label import compute_labeling_stats, label_flows


def test_temporal_overlap_labels_attack():
    event_ts = datetime(2026, 6, 13, 1, 44, 32, tzinfo=timezone.utc)
    event_ms = int(event_ts.timestamp() * 1000)

    metadata = pd.DataFrame([{
        "absolute_timestamp": event_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "_ts_parsed": event_ts,
        "relative_timestamp_s": 10.0,
        "event_kind": "attack",
        "source_ip": "10.0.0.1",
        "target_ip": "10.0.0.2",
        "action": "port_scan",
        "label": "port_scan",
        "duration_s": 60.0,
    }])

    capture_start = event_ts - timedelta(seconds=10)

    flows = pd.DataFrame([
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "bidirectional_first_seen_ms": event_ms + 1000,
            "bidirectional_last_seen_ms": event_ms + 5000,
        },
        {
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.88",
            "bidirectional_first_seen_ms": event_ms + 200000,
            "bidirectional_last_seen_ms": event_ms + 300000,
        },
    ])

    labeled = label_flows(flows, metadata, capture_started_at=capture_start)
    stats = compute_labeling_stats(labeled)

    assert stats.attack_flows == 1
    assert stats.background_flows == 1
    assert labeled.iloc[0]["flow_label"] == "attack"
