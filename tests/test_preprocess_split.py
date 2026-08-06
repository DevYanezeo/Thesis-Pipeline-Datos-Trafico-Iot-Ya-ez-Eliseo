"""Pruebas del split sin fuga (pipeline/split.py)."""
from __future__ import annotations

import pytest

from tests.ml_fixtures import make_flows

pytest.importorskip("sklearn")

from pipeline.dataset_spec import resolve_target  # noqa: E402
from pipeline.split import split_dataset  # noqa: E402


def test_episode_split_no_group_overlap():
    df = make_flows(seed=1)
    filtered, y, _ = resolve_target(df, "three-class")

    train, test, meta = split_dataset(
        filtered, y, test_size=0.2, split_by="episode", stratify=True, seed=42
    )

    # Ningun episodio (event_id no vacio) puede estar en train y test a la vez.
    train_ev = {e for e in train["event_id"].astype(str) if e.strip()}
    test_ev = {e for e in test["event_id"].astype(str) if e.strip()}
    assert train_ev.isdisjoint(test_ev)
    assert meta["group_overlap"] == 0


def test_episode_split_ratio_and_classes_present():
    df = make_flows(seed=2)
    filtered, y, _ = resolve_target(df, "three-class")

    train, test, meta = split_dataset(
        filtered, y, test_size=0.2, split_by="episode", stratify=True, seed=7
    )

    assert abs(meta["achieved_test_fraction"] - 0.2) <= 0.1
    for cls in ("attack", "benign", "background"):
        assert meta["train_class_counts"].get(cls, 0) > 0
        assert meta["test_class_counts"].get(cls, 0) > 0


def test_temporal_split_is_ordered():
    df = make_flows(seed=3)
    filtered, y, _ = resolve_target(df, "three-class")

    train, test, _ = split_dataset(
        filtered, y, test_size=0.25, split_by="temporal", stratify=False, seed=0
    )

    # Todo el train ocurre antes (o igual) que cualquier flujo de test.
    assert train["bidirectional_first_seen_ms"].max() <= test["bidirectional_first_seen_ms"].min()


def test_attack_benign_mode_drops_background():
    df = make_flows(seed=4)
    filtered, y, class_names = resolve_target(df, "attack-benign")
    assert set(class_names) == {"attack", "benign"}

    train, test, _ = split_dataset(
        filtered, y, test_size=0.2, split_by="episode", stratify=True, seed=1
    )
    assert "background" not in set(train["flow_label"]) | set(test["flow_label"])
