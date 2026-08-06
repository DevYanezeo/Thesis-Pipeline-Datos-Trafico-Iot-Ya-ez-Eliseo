import pandas as pd

from pipeline.early_packets import apply_full_flow_metadata, apply_packet_horizon_metadata_only


def test_full_flow_mode():
    flows = pd.DataFrame({"bidirectional_packets": [5, 100, 3]})
    out = apply_full_flow_metadata(flows)
    assert (out["extraction_mode"] == "full_flow").all()
    assert out["packet_horizon_n"].isna().all()
    assert out["used_packet_count"].tolist() == [5, 100, 3]
    assert "timestamp_start" in out.columns
    assert "flow_id" not in out.columns  # assign_flow_ids is in extract path


def test_metadata_only_horizon():
    flows = pd.DataFrame({
        "bidirectional_packets": [5, 100, 3],
        "bidirectional_bytes": [500, 10000, 300],
        "bidirectional_first_seen_ms": [1000, 2000, 3000],
        "bidirectional_last_seen_ms": [2000, 9000, 3500],
    })
    out = apply_packet_horizon_metadata_only(flows, 10)
    assert (out["extraction_mode"] == "first_n_packets").all()
    assert (out["packet_horizon_n"] == 10).all()
    assert out["used_packet_count"].tolist() == [5, 10, 3]
    assert out["bidirectional_packets"].tolist() == [5, 10, 3]
    assert out["bidirectional_bytes"].tolist() == [500, 1000, 300]


def test_metadata_only_respects_max_n():
    flows = pd.DataFrame({"bidirectional_packets": [100], "bidirectional_bytes": [10000]})
    out5 = apply_packet_horizon_metadata_only(flows, 5)
    out10 = apply_packet_horizon_metadata_only(flows, 10)
    assert out5.iloc[0]["bidirectional_packets"] == 5
    assert out10.iloc[0]["bidirectional_packets"] == 10
    assert out5.iloc[0]["bidirectional_bytes"] < out10.iloc[0]["bidirectional_bytes"]
