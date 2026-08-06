from pathlib import Path

import pytest

from pipeline.ingest import ingest

SAMPLE_CSV = Path(__file__).resolve().parents[1] / "sample_data" / "EXP-DEMO-001-run01.csv"


def test_ingest_demo_csv_columns():
    with pytest.raises(FileNotFoundError):
        ingest("/nonexistent.pcap", SAMPLE_CSV)

    # Sin PCAP real: solo validar que el CSV parsea si existiera PCAP
    assert SAMPLE_CSV.exists()
    from pipeline.ingest import _read_metadata_csv

    df = _read_metadata_csv(SAMPLE_CSV)
    assert len(df) == 3
    assert "_ts_parsed" in df.columns
    assert df["event_kind"].isin(["attack", "benign"]).all()
