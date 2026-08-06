from pipeline.flow_ids import assign_flow_ids
import pandas as pd


def test_assign_flow_ids_from_nfstream_id():
    flows = pd.DataFrame({"id": [42, 99], "src_ip": ["1.1.1.1", "2.2.2.2"]})
    out = assign_flow_ids(flows)
    assert out["flow_id"].tolist() == ["42", "99"]


def test_assign_flow_ids_stable_hash():
    flows = pd.DataFrame({
        "src_ip": ["10.0.0.1"],
        "dst_ip": ["10.0.0.2"],
        "src_port": [80],
        "dst_port": [443],
        "protocol": [6],
        "bidirectional_first_seen_ms": [1000],
    })
    out = assign_flow_ids(flows)
    assert out["flow_id"].iloc[0].startswith("flow-")
