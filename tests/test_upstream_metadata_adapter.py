import json
from pathlib import Path

from pipeline.adapters.upstream_metadata_json import convert_upstream_json_to_csv
from pipeline.ingest import _read_metadata_csv

FIXTURE_JSON = Path(__file__).resolve().parents[1] / "fixtures" / "upstream-run-00" / "metadata.json"
FIXTURE_PCAP = Path(__file__).resolve().parents[1] / "fixtures" / "upstream-run-00" / "capture.pcap"

SAMPLE_UPSTREAM_JSON = {
    "experiment_id": "00",
    "environment": "test-env",
    "orchestrator_version": "1.0.0",
    "started_at": "2026-06-13T01:44:22.467428+00:00",
    "planned_duration_s": 120,
    "events": [
        {
            "offset_s": 10,
            "event_type": "benign",
            "action": "take_snapshot",
            "source": "192.168.1.84",
            "target": "192.168.1.81",
            "duration_s": 10,
            "label": "take_snapshot",
        },
        {
            "offset_s": 20,
            "event_type": "attack",
            "action": "port_scan",
            "source": "172.19.103.156",
            "target": "192.168.1.81",
            "duration_s": 60,
            "label": "port_scan",
        },
    ],
}


def test_convert_upstream_json_to_csv(tmp_path: Path):
    json_path = tmp_path / "metadata.json"
    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_bytes(b"\x00\x01")
    json_path.write_text(json.dumps(SAMPLE_UPSTREAM_JSON), encoding="utf-8")

    out = tmp_path / "out.csv"
    convert_upstream_json_to_csv(json_path, pcap_path, out)

    assert out.exists()
    df = _read_metadata_csv(out)
    assert len(df) == 2
    assert set(df["event_kind"]) == {"benign", "attack"}
    assert df.iloc[0]["source_ip"] == "192.168.1.84"


def test_convert_real_fixture_if_present(tmp_path: Path):
    if not FIXTURE_JSON.exists():
        return
    pcap = FIXTURE_PCAP if FIXTURE_PCAP.exists() else tmp_path / "capture.pcap"
    if not pcap.exists():
        pcap.write_bytes(b"\x00\x01")
    out = tmp_path / "converted.csv"
    convert_upstream_json_to_csv(FIXTURE_JSON, pcap, out)
    df = _read_metadata_csv(out)
    assert len(df) >= 1


def test_ordered_pcaps_keeps_initial_segment_and_parts(tmp_path: Path):
    from pipeline.adapters.upstream_metadata_json import ordered_pcap_paths

    full = tmp_path / "01_20260727_173703.pcap"
    p1 = tmp_path / "01_20260727_173703_part1.pcap"
    p2 = tmp_path / "01_20260727_173703_part2.pcap"
    for p in (full, p1, p2):
        p.write_bytes(b"\x00")

    payload = {
        "artifacts": [
            {"type": "PCAP", "name": full.name},
            {"type": "PCAP", "name": p1.name},
            {"type": "PCAP", "name": p2.name},
        ]
    }
    ordered = ordered_pcap_paths(payload, tmp_path)
    # El .pcap sin _part es el segmento inicial (21:37→…), no un duplicado.
    assert [p.name for p in ordered] == [full.name, p1.name, p2.name]


def test_scheduled_dt_and_zero_duration_semantics():
    from pipeline.adapters.upstream_metadata_json import json_to_events_dataframe

    payload = {
        "experiment_id": "01",
        "started_at": "2026-07-27T21:37:04.055431+00:00",
        "events": [
            {
                "scheduled_dt": "27/07/2026 17:42:03",
                "offset_s": None,
                "event_type": "attack",
                "action": "tcp_flood",
                "source": "192.168.1.88",
                "target": "192.168.1.86",
                "duration_s": 30,
                "label": "attack",
            },
            {
                "scheduled_dt": "27/07/2026 17:47:03",
                "offset_s": None,
                "event_type": "benign",
                "action": "take_snapshot_auth",
                "source": "192.168.1.88",
                "target": "192.168.1.82",
                "duration_s": 0,
                "label": "benign",
            },
            {
                "scheduled_dt": "27/07/2026 18:37:03",
                "offset_s": None,
                "event_type": "attack",
                "action": "port_scan",
                "source": "192.168.1.88",
                "target": "192.168.1.86",
                "duration_s": 0,
                "label": "attack",
            },
        ],
    }
    df = json_to_events_dataframe(payload, None)
    assert df["absolute_timestamp"].nunique() == 3
    assert df.iloc[0]["absolute_timestamp"].startswith("2026-07-27T21:42:03")
    assert float(df.iloc[0]["duration_s"]) == 30.0
    # duration_s=0 → ventana mínima 1 s (singular / benigno corto)
    assert float(df.iloc[1]["duration_s"]) == 1.0
    assert float(df.iloc[2]["duration_s"]) == 1.0
