import json
from pathlib import Path

import pytest

from pipeline.ingest import ingest

FIXTURE_JSON = Path(__file__).resolve().parents[1] / "fixtures" / "upstream-run-00" / "metadata.json"


def test_ingest_json_metadata_format(tmp_path: Path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00\x01\x02")
    meta = tmp_path / "events.json"
    meta.write_text(
        json.dumps({
            "experiment_id": "00",
            "started_at": "2026-06-13T01:44:22.467428+00:00",
            "events": [
                {
                    "event_id": "e1",
                    "offset_s": 0,
                    "event_type": "attack",
                    "action": "port_scan",
                    "source": "10.0.0.1",
                    "target": "10.0.0.2",
                    "duration_s": 5,
                    "label": "port_scan",
                }
            ],
        }),
        encoding="utf-8",
    )

    result = ingest(pcap, meta)
    assert result.metadata_format == "json"
    assert result.experiment_id == "00"
    assert len(result.metadata) == 1
    assert result.metadata.iloc[0]["event_kind"] == "attack"
    assert result.metadata.iloc[0]["event_id"] == "e1"


def test_ingest_real_fixture_json_if_present(tmp_path: Path):
    if not FIXTURE_JSON.exists():
        pytest.skip("fixture JSON no disponible")
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00\x01")
    result = ingest(pcap, FIXTURE_JSON)
    assert result.metadata_format == "json"
    assert len(result.metadata) == 3
