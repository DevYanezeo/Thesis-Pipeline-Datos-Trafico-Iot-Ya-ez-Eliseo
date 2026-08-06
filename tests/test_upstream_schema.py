"""Tests del esquema JSON upstream (jul-2026): taxonomía y mitre_ref."""
import json
from pathlib import Path

import pandas as pd
import pytest

from pipeline.adapters.upstream_metadata_json import (
    _parse_mitre_ref,
    _stable_event_id,
    json_to_events_dataframe,
    resolve_pcap_paths_from_artifacts,
)
from pipeline.ingest import ingest
from pipeline.label import label_flows

UPSTREAM_JSON = Path(__file__).resolve().parents[1] / (
    "fixtures/upstream-run-01/metadata.json"
)

SAMPLE_UPSTREAM = {
    "experiment_id": "00",
    "started_at": "2026-07-02T23:10:59.465111+00:00",
    "events": [
        {
            "event_type": "attack",
            "action": "dos_http",
            "target": "192.168.1.82",
            "source": "192.168.1.89",
            "offset_s": 3600,
            "duration_s": 60,
            "label": "attack",
            "sublabel": "artificial",
            "category": "Actions on Objectives",
            "subcategory": "denial_of_service",
            "mitre_ref": "T1499.001",
            "tool": "slowloris",
        },
        {
            "event_type": "benign",
            "action": "take_snapshot_auth",
            "target": "192.168.1.82",
            "source": "192.168.1.89",
            "offset_s": 600,
            "duration_s": 30,
            "label": "benign",
            "sublabel": "artificial",
        },
    ],
}


def test_parse_mitre_ref():
    assert _parse_mitre_ref("T1498.001") == ("T1498", "001")
    assert _parse_mitre_ref("") == ("", "")


def test_stable_event_id_is_deterministic():
    event = {"offset_s": 300, "action": "scapy_syn_flood", "source": "1.2.3.4", "target": "5.6.7.8", "event_type": "attack"}
    a = _stable_event_id(event, 1, "20260702_191058")
    b = _stable_event_id(event, 1, "20260702_191058")
    assert a == b
    assert len(a) == 8


def test_json_to_events_dataframe_upstream_fields():
    df = json_to_events_dataframe(SAMPLE_UPSTREAM)
    assert len(df) == 2
    attack = df.iloc[0]
    assert attack["event_kind"] == "attack"
    assert attack["mitre_ref"] == "T1499.001"
    assert attack["mitre_technique"] == "T1499"
    assert attack["mitre_subtechnique"] == "001"
    assert attack["category"] == "Actions on Objectives"
    assert attack["subcategory"] == "denial_of_service"
    assert attack["sublabel"] == "artificial"
    assert attack["tool"] == "slowloris"
    assert attack["event_id"]


def test_label_flows_propagates_taxonomy():
    from datetime import datetime, timezone

    event_ts = datetime(2026, 7, 2, 23, 10, 59, tzinfo=timezone.utc)
    event_ms = int((event_ts.timestamp() + 3600) * 1000)

    metadata = json_to_events_dataframe(SAMPLE_UPSTREAM)
    metadata["_ts_parsed"] = pd.to_datetime(metadata["absolute_timestamp"], utc=True)

    flows = pd.DataFrame([{
        "src_ip": "192.168.1.89",
        "dst_ip": "192.168.1.82",
        "bidirectional_first_seen_ms": event_ms + 1000,
        "bidirectional_last_seen_ms": event_ms + 5000,
    }])

    labeled = label_flows(flows, metadata, capture_started_at=event_ts)
    row = labeled.iloc[0]
    assert row["flow_label"] == "attack"
    assert row["mitre_label"] == "dos_http"
    assert row["attack_category"] == "Actions on Objectives"
    assert row["attack_subcategory"] == "denial_of_service"
    assert row["mitre_ref"] == "T1499.001"
    assert row["event_sublabel"] == "artificial"
    assert row["event_tool"] == "slowloris"


def test_resolve_pcap_paths_from_artifacts(tmp_path: Path):
    (tmp_path / "00_20260702_191058.pcap").write_bytes(b"x")
    (tmp_path / "00_20260702_191058_part1.pcap").write_bytes(b"y")
    payload = {
        "artifacts": [
            {"name": "00_20260702_191058.pcap", "type": "PCAP", "path": "outputs/pcap/00_20260702_191058.pcap"},
            {"name": "00_20260702_191058_part1.pcap", "type": "PCAP", "path": "outputs/pcap/00_20260702_191058_part1.pcap"},
        ]
    }
    paths = resolve_pcap_paths_from_artifacts(payload, base_dir=tmp_path)
    assert len(paths) == 2
    assert paths[0].name == "00_20260702_191058.pcap"


def test_ingest_real_upstream_fixture_if_present(tmp_path: Path):
    if not UPSTREAM_JSON.exists():
        pytest.skip("fixture upstream-run-01 no disponible")
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00\x01")
    result = ingest(pcap, UPSTREAM_JSON)
    assert result.metadata_format == "json"
    assert len(result.metadata) == 5
    assert "mitre_ref" in result.metadata.columns
