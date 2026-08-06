import pytest

from pipeline.cli import _parse_horizons, _validate_horizons
from pipeline.privacy import apply_privacy


def test_validate_horizons_strictly_increasing():
    assert _validate_horizons([5, 10, 20]) == [5, 10, 20]


def test_validate_horizons_rejects_non_increasing():
    with pytest.raises(ValueError, match="estrictamente crecientes"):
        _validate_horizons([10, 5])


def test_validate_horizons_rejects_duplicates():
    with pytest.raises(ValueError, match="no pueden repetirse"):
        _validate_horizons([5, 5, 10])


def test_parse_horizons_without_full_by_default():
    assert _parse_horizons(None, "5,10,20", include_full=False) == [5, 10, 20]


def test_parse_horizons_with_full_flag():
    assert _parse_horizons(None, "5,10,20", include_full=True) == [None, 5, 10, 20]


def test_parse_horizons_single_without_full():
    assert _parse_horizons(10, None, include_full=False) == [10]


def test_parse_horizons_default_only_full():
    assert _parse_horizons(None, None, include_full=False) == [None]


def test_privacy_pseudonymize_changes_ips():
    df = __import__("pandas").DataFrame({"src_ip": ["192.168.1.1"], "dst_ip": ["10.0.0.2"]})
    out = apply_privacy(df, "pseudonymize")
    assert out.iloc[0]["src_ip"].startswith("psn-")
    assert out.iloc[0]["dst_ip"].startswith("psn-")


def test_privacy_none_passthrough():
    df = __import__("pandas").DataFrame({"src_ip": ["192.168.1.1"]})
    out = apply_privacy(df, "none")
    assert out.iloc[0]["src_ip"] == "192.168.1.1"


def test_cli_exposes_nfstream_timeout_flags():
    from pipeline.cli import DEFAULT_ACTIVE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_N_DISSECTIONS, main
    from unittest.mock import patch

    captured: dict = {}

    def _fake_run(*args, **kwargs):
        captured.update(kwargs)
        captured["positional"] = args
        return 0

    with patch("pipeline.cli.run_pipeline", side_effect=_fake_run):
        rc = main(
            [
                "run",
                "--pcap",
                "x.pcap",
                "--metadata",
                "m.json",
                "--output",
                "out/",
                "--idle-timeout",
                "60",
                "--active-timeout",
                "900",
                "--n-dissections",
                "10",
                "--packet-horizons",
                "3,7,15",
            ]
        )
    assert rc == 0
    assert captured["idle_timeout"] == 60
    assert captured["active_timeout"] == 900
    assert captured["n_dissections"] == 10
    assert captured["positional"][4] is None  # packet_horizon single
    assert captured["positional"][5] == "3,7,15"


def test_cli_nfstream_timeout_defaults():
    from unittest.mock import patch

    from pipeline.cli import DEFAULT_ACTIVE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_N_DISSECTIONS, main

    captured: dict = {}

    def _fake_run(*args, **kwargs):
        captured.update(kwargs)
        return 0

    with patch("pipeline.cli.run_pipeline", side_effect=_fake_run):
        rc = main(
            [
                "run",
                "--pcap",
                "x.pcap",
                "--metadata",
                "m.json",
                "--output",
                "out/",
            ]
        )
    assert rc == 0
    assert captured["idle_timeout"] == DEFAULT_IDLE_TIMEOUT
    assert captured["active_timeout"] == DEFAULT_ACTIVE_TIMEOUT
    assert captured["n_dissections"] == DEFAULT_N_DISSECTIONS


def test_run_pipeline_rejects_non_positive_timeouts(tmp_path):
    from pipeline.cli import EXIT_USAGE, run_pipeline

    rc = run_pipeline(
        tmp_path / "a.pcap",
        tmp_path / "m.json",
        tmp_path / "out",
        False,
        None,
        None,
        include_full=False,
        statistical_analysis=True,
        privacy_mode="none",
        idle_timeout=0,
        active_timeout=1800,
    )
    assert rc == EXIT_USAGE
