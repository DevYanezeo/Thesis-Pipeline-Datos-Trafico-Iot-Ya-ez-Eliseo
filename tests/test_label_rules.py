"""Cobertura de reglas de etiquetado evento->flujo (pedido explicito Iturbe, bitacora 4.2).

Reglas verificadas:
- Prioridad attack > benign cuando ambos solapan.
- El match por IP (5-tupla) es obligatorio para heredar etiqueta.
- Un evento sin IPs declaradas etiqueta cualquier flujo que solape en tiempo.
- duration_s=0 usa una ventana minima de 1 s (caso syn_flood / evento instantaneo).
- Sin solape temporal el flujo queda como background aunque la IP calce.
- Solo un evento benigno solapando produce etiqueta benign.
- La taxonomia del evento (category/subcategory/mitre_ref/tool/sublabel/event_id) se propaga al flujo.
"""
from datetime import datetime, timezone

import pandas as pd

from pipeline.label import compute_labeling_stats, label_flows

EVENT_TS = datetime(2026, 6, 13, 1, 44, 32, tzinfo=timezone.utc)
EVENT_MS = int(EVENT_TS.timestamp() * 1000)


def _event(**overrides) -> dict:
    base = {
        "_ts_parsed": EVENT_TS,
        "event_kind": "attack",
        "source_ip": "10.0.0.1",
        "target_ip": "10.0.0.2",
        "action": "port_scan",
        "label": "attack",
        "sublabel": "artificial",
        "category": "",
        "subcategory": "",
        "mitre_ref": "",
        "tool": "",
        "event_id": "evt-1",
        "duration_s": 60.0,
    }
    base.update(overrides)
    return base


def _flow(**overrides) -> dict:
    base = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "bidirectional_first_seen_ms": EVENT_MS + 1000,
        "bidirectional_last_seen_ms": EVENT_MS + 5000,
    }
    base.update(overrides)
    return base


def test_attack_priority_over_benign():
    """Un flujo que solapa un ataque y un benigno simultaneos hereda attack."""
    metadata = pd.DataFrame([
        _event(event_kind="benign", label="benign", action="take_snapshot", event_id="evt-b"),
        _event(event_kind="attack", label="attack", action="port_scan", event_id="evt-a"),
    ])
    flows = pd.DataFrame([_flow()])

    labeled = label_flows(flows, metadata, capture_started_at=None)

    assert labeled.iloc[0]["flow_label"] == "attack"
    assert labeled.iloc[0]["event_id"] == "evt-a"


def test_ip_mismatch_forces_background():
    """Solape temporal pero IPs que no calzan -> background."""
    metadata = pd.DataFrame([_event()])
    flows = pd.DataFrame([_flow(src_ip="192.168.5.5", dst_ip="192.168.5.6")])

    labeled = label_flows(flows, metadata, capture_started_at=None)

    assert labeled.iloc[0]["flow_label"] == "background"


def test_event_without_ips_matches_any_flow():
    """Evento sin IPs declaradas etiqueta cualquier flujo que solape en tiempo."""
    metadata = pd.DataFrame([_event(source_ip="", target_ip="")])
    flows = pd.DataFrame([_flow(src_ip="172.16.9.9", dst_ip="172.16.9.10")])

    labeled = label_flows(flows, metadata, capture_started_at=None)

    assert labeled.iloc[0]["flow_label"] == "attack"


def test_zero_duration_uses_minimum_window():
    """duration_s=0 (syn_flood) usa ventana minima de 1 s: un flujo en el instante calza."""
    metadata = pd.DataFrame([_event(duration_s=0.0, action="syn_flood")])
    flows = pd.DataFrame([_flow(
        bidirectional_first_seen_ms=EVENT_MS,
        bidirectional_last_seen_ms=EVENT_MS + 500,
    )])

    labeled = label_flows(flows, metadata, capture_started_at=None)

    assert labeled.iloc[0]["flow_label"] == "attack"


def test_no_temporal_overlap_stays_background():
    """IP calza pero el flujo esta fuera de la ventana del evento -> background."""
    metadata = pd.DataFrame([_event(duration_s=10.0)])
    flows = pd.DataFrame([_flow(
        bidirectional_first_seen_ms=EVENT_MS + 60_000,
        bidirectional_last_seen_ms=EVENT_MS + 65_000,
    )])

    labeled = label_flows(flows, metadata, capture_started_at=None)

    assert labeled.iloc[0]["flow_label"] == "background"


def test_benign_only_overlap_labels_benign():
    """Solo un evento benigno solapando produce etiqueta benign."""
    metadata = pd.DataFrame([
        _event(event_kind="benign", label="benign", action="take_snapshot", event_id="evt-b"),
    ])
    flows = pd.DataFrame([_flow()])

    labeled = label_flows(flows, metadata, capture_started_at=None)

    assert labeled.iloc[0]["flow_label"] == "benign"
    assert labeled.iloc[0]["event_id"] == "evt-b"


def test_taxonomy_fields_propagated():
    """La taxonomia del evento se propaga a las columnas del flujo etiquetado."""
    metadata = pd.DataFrame([_event(
        category="Actions on Objectives",
        subcategory="denial_of_service",
        mitre_ref="T1499.001",
        tool="slowloris",
        sublabel="artificial",
        action="dos_http",
        event_id="evt-x",
    )])
    flows = pd.DataFrame([_flow()])

    row = label_flows(flows, metadata, capture_started_at=None).iloc[0]

    assert row["attack_category"] == "Actions on Objectives"
    assert row["attack_subcategory"] == "denial_of_service"
    assert row["mitre_ref"] == "T1499.001"
    assert row["event_tool"] == "slowloris"
    assert row["event_sublabel"] == "artificial"
    assert row["event_action"] == "dos_http"
    assert row["event_id"] == "evt-x"


def test_stats_counts_are_consistent():
    """attack + benign + background == total y conteos por clase correctos."""
    metadata = pd.DataFrame([
        _event(event_kind="attack", source_ip="10.0.0.1", target_ip="10.0.0.2", event_id="a1"),
        _event(event_kind="benign", label="benign", source_ip="10.0.0.3",
                target_ip="10.0.0.4", event_id="b1"),
    ])
    flows = pd.DataFrame([
        _flow(src_ip="10.0.0.1", dst_ip="10.0.0.2"),          # attack
        _flow(src_ip="10.0.0.3", dst_ip="10.0.0.4"),          # benign
        _flow(src_ip="8.8.8.8", dst_ip="8.8.4.4"),            # background (IP no calza)
    ])

    labeled = label_flows(flows, metadata, capture_started_at=None)
    stats = compute_labeling_stats(labeled)

    assert stats.total_flows == 3
    assert stats.attack_flows == 1
    assert stats.benign_flows == 1
    assert stats.background_flows == 1
    assert stats.labeled_flows == 2
