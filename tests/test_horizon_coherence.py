"""Tests de coherencia entre horizontes N (bidirectional_packets vs used_packet_count)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest

from pipeline.early_packets import (
    _canonical_key,
    _cap_packets_bytes,
    apply_early_packet_stats,
    apply_packet_horizon_metadata_only,
)


def _flow_row(
    *,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 1234,
    dport: int = 80,
    packets: int = 100,
    bytes_: int = 10_000,
    first_ms: int = 1_000,
    last_ms: int = 9_000,
) -> dict:
    return {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": 6,
        "bidirectional_packets": packets,
        "bidirectional_bytes": bytes_,
        "bidirectional_first_seen_ms": first_ms,
        "bidirectional_last_seen_ms": last_ms,
        "bidirectional_duration_ms": last_ms - first_ms,
    }


def _assert_horizon_coherent(df: pd.DataFrame, horizon: int) -> None:
    """Invariante: contadores alineados y acotados por N."""
    assert (df["packet_horizon_n"] == horizon).all()
    assert (df["extraction_mode"] == "first_n_packets").all()
    assert (df["bidirectional_packets"] == df["used_packet_count"]).all()
    assert (df["bidirectional_packets"] <= horizon).all()
    assert (df["used_packet_count"] <= horizon).all()
    assert (df["bidirectional_packets"] <= df["original_flow_packet_count"]).all()


# --- _cap_packets_bytes ---


@pytest.mark.parametrize(
    ("packets", "bytes_", "horizon", "exp_packets", "exp_bytes"),
    [
        (100, 10_000, 5, 5, 500),
        (3, 300, 10, 3, 300),
        (0, 0, 5, 0, 0),
        (5, 500, 5, 5, 500),
    ],
)
def test_cap_packets_bytes(packets, bytes_, horizon, exp_packets, exp_bytes):
    capped_p, capped_b = _cap_packets_bytes(packets, bytes_, horizon)
    assert capped_p == exp_packets
    assert capped_b == exp_bytes


# --- metadata-only ---


def test_metadata_only_all_columns_coherent():
    flows = pd.DataFrame([
        _flow_row(packets=5, bytes_=500),
        _flow_row(packets=100, bytes_=10_000),
        _flow_row(packets=3, bytes_=300),
    ])
    out = apply_packet_horizon_metadata_only(flows, 10)
    _assert_horizon_coherent(out, 10)
    assert out["bidirectional_packets"].tolist() == [5, 10, 3]
    assert out["bidirectional_bytes"].tolist() == [500, 1000, 300]


@pytest.mark.parametrize("horizon", [5, 10, 20])
def test_metadata_only_respects_horizon_max(horizon: int):
    flows = pd.DataFrame([_flow_row(packets=500, bytes_=50_000)])
    out = apply_packet_horizon_metadata_only(flows, horizon)
    _assert_horizon_coherent(out, horizon)
    assert out.iloc[0]["bidirectional_packets"] == horizon


def test_metadata_only_n5_less_than_n10_on_long_flow():
    flows = pd.DataFrame([_flow_row(packets=50, bytes_=5_000)])
    out5 = apply_packet_horizon_metadata_only(flows, 5)
    out10 = apply_packet_horizon_metadata_only(flows, 10)
    assert out5.iloc[0]["bidirectional_packets"] == 5
    assert out10.iloc[0]["bidirectional_packets"] == 10
    assert out5.iloc[0]["bidirectional_bytes"] < out10.iloc[0]["bidirectional_bytes"]


def test_metadata_only_preserves_original_flow_packet_count():
    flows = pd.DataFrame([_flow_row(packets=216, bytes_=21_600)])
    out = apply_packet_horizon_metadata_only(flows, 5)
    assert out.iloc[0]["original_flow_packet_count"] == 216
    assert out.iloc[0]["bidirectional_packets"] == 5


# --- apply_early_packet_stats (mock PCAP) ---


def test_early_stats_empty_pcap_dict_uses_metadata_fallback():
    flows = pd.DataFrame([_flow_row(packets=80, bytes_=8_000)])
    with patch("pipeline.early_packets.compute_early_packet_stats", return_value={}):
        out = apply_early_packet_stats(flows, Path("/fake.pcap"), 5)
    _assert_horizon_coherent(out, 5)
    assert out.iloc[0]["bidirectional_packets"] == 5
    assert out.iloc[0]["bidirectional_bytes"] == 500


def test_early_stats_unmatched_flow_fallback_not_full_count():
    """Flujo sin match en PCAP: no debe quedar bidirectional_packets=100 con N=5."""
    flows = pd.DataFrame([_flow_row(packets=100, bytes_=10_000)])
    with patch("pipeline.early_packets.compute_early_packet_stats", return_value={}):
        out = apply_early_packet_stats(flows, Path("/fake.pcap"), 5)
    row = out.iloc[0]
    assert row["bidirectional_packets"] == 5
    assert row["used_packet_count"] == 5
    assert row["bidirectional_packets"] != row["original_flow_packet_count"]


def test_early_stats_matched_flow_uses_pcap_counters():
    flows = pd.DataFrame([_flow_row(packets=100, bytes_=10_000)])
    key = _canonical_key("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    early = {
        key: {
            "bidirectional_packets": 3,
            "bidirectional_bytes": 180,
            "bidirectional_first_seen_ms": 1000,
            "bidirectional_last_seen_ms": 1500,
            "bidirectional_duration_ms": 500,
        }
    }
    with patch("pipeline.early_packets.compute_early_packet_stats", return_value=early):
        out = apply_early_packet_stats(flows, Path("/fake.pcap"), 5)
    row = out.iloc[0]
    assert row["bidirectional_packets"] == 3
    assert row["used_packet_count"] == 3
    assert row["bidirectional_bytes"] == 180


def test_early_stats_canonical_key_matches_reversed_ips():
    """NFStream puede invertir src/dst; la 5-tupla canónica debe emparejar."""
    flows = pd.DataFrame([
        _flow_row(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234, packets=50),
    ])
    key = _canonical_key("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    early = {
        key: {
            "bidirectional_packets": 4,
            "bidirectional_bytes": 400,
            "bidirectional_first_seen_ms": 2000,
            "bidirectional_last_seen_ms": 3000,
            "bidirectional_duration_ms": 1000,
        }
    }
    with patch("pipeline.early_packets.compute_early_packet_stats", return_value=early):
        out = apply_early_packet_stats(flows, Path("/fake.pcap"), 10)
    assert out.iloc[0]["bidirectional_packets"] == 4


def test_early_stats_mixed_matched_and_fallback_rows():
    flows = pd.DataFrame([
        _flow_row(src="10.0.0.1", dst="10.0.0.2", packets=100),
        _flow_row(src="192.168.1.50", dst="8.8.8.8", sport=53, dport=40000, packets=33),
    ])
    key = _canonical_key("10.0.0.1", "10.0.0.2", 1234, 80, 6)
    early = {
        key: {
            "bidirectional_packets": 5,
            "bidirectional_bytes": 500,
            "bidirectional_first_seen_ms": 1000,
            "bidirectional_last_seen_ms": 2000,
            "bidirectional_duration_ms": 1000,
        }
    }
    with patch("pipeline.early_packets.compute_early_packet_stats", return_value=early):
        out = apply_early_packet_stats(flows, Path("/fake.pcap"), 5)
    _assert_horizon_coherent(out, 5)
    assert out.iloc[0]["bidirectional_packets"] == 5
    assert out.iloc[1]["bidirectional_packets"] == 5
    assert out.iloc[1]["original_flow_packet_count"] == 33


def test_horizon_variants_differ_only_where_expected():
    """n5 y n10 deben coincidir en flujos cortos y diferir en flujos 6–10 paquetes."""
    flows = pd.DataFrame([
        _flow_row(packets=3),
        _flow_row(packets=8),
        _flow_row(packets=25),
    ])
    out5 = apply_packet_horizon_metadata_only(flows, 5)
    out10 = apply_packet_horizon_metadata_only(flows, 10)
    out20 = apply_packet_horizon_metadata_only(flows, 20)

    assert out5.iloc[0]["bidirectional_packets"] == out10.iloc[0]["bidirectional_packets"] == 3
    assert out5.iloc[1]["bidirectional_packets"] == 5
    assert out10.iloc[1]["bidirectional_packets"] == 8
    assert out5.iloc[2]["bidirectional_packets"] == 5
    assert out10.iloc[2]["bidirectional_packets"] == 10
    assert out20.iloc[2]["bidirectional_packets"] == 20
