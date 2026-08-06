"""Estadísticas de flujo a partir de los primeros N paquetes (detección temprana)."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


def _canonical_key(src: str, dst: str, sport: int, dport: int, proto: int) -> tuple:
    left = (str(src), int(sport or 0))
    right = (str(dst), int(dport or 0))
    if left <= right:
        return (left[0], left[1], right[0], right[1], int(proto))
    return (right[0], right[1], left[0], left[1], int(proto))


def _flow_row_key(row: pd.Series) -> tuple:
    return _canonical_key(
        str(row.get("src_ip", "")),
        str(row.get("dst_ip", "")),
        int(row.get("src_port", 0) or 0),
        int(row.get("dst_port", 0) or 0),
        int(row.get("protocol", 0) or 0),
    )


def compute_early_packet_stats(
    pcap_path: Path | list[Path],
    packet_horizon: int,
) -> dict[tuple, dict[str, Any]]:
    """Agrega por flujo bidireccional usando solo los primeros N paquetes cronológicos."""
    from scapy.all import IP, TCP, UDP
    from scapy.utils import PcapReader

    if packet_horizon <= 0:
        return {}

    paths = [pcap_path] if isinstance(pcap_path, Path) else list(pcap_path)
    buckets: dict[tuple, list[tuple[int, int]]] = {}

    for path in paths:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                if not pkt.haslayer(IP):
                    continue
                ip = pkt[IP]
                sport = dport = 0
                if pkt.haslayer(TCP):
                    sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
                    proto = 6
                elif pkt.haslayer(UDP):
                    sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
                    proto = 17
                else:
                    proto = int(ip.proto)

                key = _canonical_key(ip.src, ip.dst, sport, dport, proto)
                packets = buckets.setdefault(key, [])
                if len(packets) >= packet_horizon:
                    continue
                ts_ms = int(float(pkt.time) * 1000)
                byte_len = len(pkt)
                packets.append((ts_ms, byte_len))

    stats: dict[tuple, dict[str, Any]] = {}
    for key, packets in buckets.items():
        if not packets:
            continue
        packets.sort(key=lambda x: x[0])
        used = packets[:packet_horizon]
        first_ms = used[0][0]
        last_ms = used[-1][0]
        stats[key] = {
            "bidirectional_packets": len(used),
            "bidirectional_bytes": sum(b for _, b in used),
            "bidirectional_first_seen_ms": first_ms,
            "bidirectional_last_seen_ms": last_ms,
            "bidirectional_duration_ms": max(last_ms - first_ms, 0),
        }
    return stats


def _cap_packets_bytes(
    original_packets: int,
    original_bytes: int,
    packet_horizon: int,
) -> tuple[int, int]:
    """Recorta contadores al horizonte N (coherencia entre columnas)."""
    capped_packets = int(min(max(original_packets, 0), packet_horizon))
    if original_packets <= 0:
        return capped_packets, 0
    if capped_packets >= original_packets:
        return capped_packets, int(original_bytes)
    scaled_bytes = int(round(original_bytes * (capped_packets / original_packets)))
    return capped_packets, scaled_bytes


def _apply_horizon_cap_to_row(
    df: pd.DataFrame,
    idx: Any,
    packet_horizon: int,
    *,
    stats: dict[str, Any] | None = None,
) -> int:
    """Aplica stats tempranas o recorte proporcional; devuelve used_packet_count."""
    original_packets = int(
        pd.to_numeric(df.at[idx, "bidirectional_packets"], errors="coerce") or 0
    )
    original_bytes = int(
        pd.to_numeric(df.get("bidirectional_bytes", pd.Series(dtype=int)).at[idx], errors="coerce")
        if "bidirectional_bytes" in df.columns
        else 0
    )

    if stats is not None:
        for col, val in stats.items():
            df.at[idx, col] = val
        return int(stats["bidirectional_packets"])

    capped_packets, capped_bytes = _cap_packets_bytes(
        original_packets, original_bytes, packet_horizon
    )
    df.at[idx, "bidirectional_packets"] = capped_packets
    if "bidirectional_bytes" in df.columns:
        df.at[idx, "bidirectional_bytes"] = capped_bytes
    if capped_packets > 0 and "bidirectional_first_seen_ms" in df.columns:
        first_ms = pd.to_numeric(
            df.at[idx, "bidirectional_first_seen_ms"], errors="coerce"
        )
        last_ms = pd.to_numeric(
            df.at[idx, "bidirectional_last_seen_ms"], errors="coerce"
        ) if "bidirectional_last_seen_ms" in df.columns else pd.NA
        if pd.notna(first_ms):
            if "bidirectional_last_seen_ms" in df.columns:
                df.at[idx, "bidirectional_last_seen_ms"] = int(first_ms)
                if pd.notna(last_ms) and capped_packets < original_packets:
                    duration = max(int(last_ms) - int(first_ms), 0)
                    scale = capped_packets / max(original_packets, 1)
                    df.at[idx, "bidirectional_last_seen_ms"] = int(first_ms + duration * scale)
            if "bidirectional_duration_ms" in df.columns and "bidirectional_last_seen_ms" in df.columns:
                df.at[idx, "bidirectional_duration_ms"] = max(
                    int(df.at[idx, "bidirectional_last_seen_ms"]) - int(first_ms), 0
                )

    return capped_packets


def apply_early_packet_stats(
    flows: pd.DataFrame,
    pcap_path: Path | list[Path],
    packet_horizon: int,
) -> pd.DataFrame:
    """Sobrescribe contadores temporales con ventana de primeros N paquetes."""
    if flows.empty or packet_horizon <= 0:
        return flows

    try:
        early = compute_early_packet_stats(pcap_path, packet_horizon)
    except Exception as exc:
        logger.warning("No se pudieron calcular stats tempranas (%s); solo metadatos de horizonte", exc)
        return apply_packet_horizon_metadata_only(flows, packet_horizon)

    if not early:
        return apply_packet_horizon_metadata_only(flows, packet_horizon)

    df = flows.copy()
    original = pd.to_numeric(df.get("bidirectional_packets", 0), errors="coerce").fillna(0).astype(int)
    df["original_flow_packet_count"] = original
    df["packet_horizon_n"] = int(packet_horizon)
    df["extraction_mode"] = "first_n_packets"

    used_counts: list[int] = []
    matched = 0
    for idx, row in df.iterrows():
        key = _flow_row_key(row)
        if key in early:
            matched += 1
            used_counts.append(
                _apply_horizon_cap_to_row(df, idx, packet_horizon, stats=early[key])
            )
        else:
            used_counts.append(
                _apply_horizon_cap_to_row(df, idx, packet_horizon, stats=None)
            )

    df["used_packet_count"] = used_counts
    logger.info(
        "Horizonte N=%d: %d/%d flujos emparejados con PCAP; %d con recorte fallback",
        packet_horizon,
        matched,
        len(df),
        len(df) - matched,
    )
    _add_timestamp_columns(df)
    return df


def apply_packet_horizon_metadata_only(flows: pd.DataFrame, packet_horizon: int) -> pd.DataFrame:
    df = flows.copy()
    original = pd.to_numeric(df.get("bidirectional_packets", 0), errors="coerce").fillna(0).astype(int)
    df["original_flow_packet_count"] = original
    df["packet_horizon_n"] = int(packet_horizon)
    df["extraction_mode"] = "first_n_packets"

    used_counts: list[int] = []
    for idx in df.index:
        used_counts.append(_apply_horizon_cap_to_row(df, idx, packet_horizon, stats=None))

    df["used_packet_count"] = used_counts
    logger.warning(
        "Horizonte N=%d en modo metadata-only: bidirectional_packets/bytes recortados sin PCAP por paquete",
        packet_horizon,
    )
    _add_timestamp_columns(df)
    return df


def apply_full_flow_metadata(flows: pd.DataFrame) -> pd.DataFrame:
    if flows.empty:
        return flows
    df = flows.copy()
    original = pd.to_numeric(df.get("bidirectional_packets", 0), errors="coerce").fillna(0).astype(int)
    df["original_flow_packet_count"] = original
    df["packet_horizon_n"] = None
    df["extraction_mode"] = "full_flow"
    df["used_packet_count"] = original
    _add_timestamp_columns(df)
    return df


def _add_timestamp_columns(df: pd.DataFrame) -> None:
    if "bidirectional_first_seen_ms" in df.columns:
        df["timestamp_start"] = pd.to_datetime(
            pd.to_numeric(df["bidirectional_first_seen_ms"], errors="coerce"),
            unit="ms",
            utc=True,
        ).astype(str)
    else:
        df["timestamp_start"] = ""
    if "bidirectional_last_seen_ms" in df.columns:
        df["timestamp_end"] = pd.to_datetime(
            pd.to_numeric(df["bidirectional_last_seen_ms"], errors="coerce"),
            unit="ms",
            utc=True,
        ).astype(str)
    else:
        df["timestamp_end"] = ""
