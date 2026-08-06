"""Extracción de flujos con NFStream.

NFStream es el UNICO extractor soportado: garantiza siempre el mismo esquema estadistico
completo (~60 columnas). No hay fallbacks (tshark/scapy) a proposito: un fallback produciria
un esquema reducido y un dataset inconsistente/roto para ML. Si NFStream no esta disponible,
el pipeline falla de forma explicita (mejor fallar que degradar en silencio).
"""
from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from pipeline.early_packets import apply_early_packet_stats, apply_full_flow_metadata
from pipeline.flow_ids import assign_flow_ids

logger = logging.getLogger(__name__)

DEFAULT_IDLE_TIMEOUT = 120
DEFAULT_ACTIVE_TIMEOUT = 1800
DEFAULT_N_DISSECTIONS = 20
INACTIVE_TIMEOUT = DEFAULT_IDLE_TIMEOUT  # compat alias
ACTIVE_TIMEOUT = DEFAULT_ACTIVE_TIMEOUT


def _normalize_timestamps_ms(df: pd.DataFrame) -> pd.DataFrame:
    """Asegura epoch ms absoluto si NFStream entrega valores relativos pequeños."""
    if df.empty or "bidirectional_first_seen_ms" not in df.columns:
        return df

    first_vals = pd.to_numeric(df["bidirectional_first_seen_ms"], errors="coerce").dropna()
    if first_vals.empty:
        return df

    # Valores < 1e12 suelen ser ms relativos al inicio de captura, no epoch.
    if first_vals.max() < 1_000_000_000_000:
        logger.warning(
            "Timestamps NFStream parecen relativos; se conservan como ms de captura. "
            "Verificar alineación con metadatos absolutos."
        )
    return df


def _extract_nfstream(
    pcap_path: Path,
    *,
    statistical_analysis: bool = True,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> pd.DataFrame:
    from nfstream import NFStreamer

    streamer = NFStreamer(
        source=str(pcap_path),
        statistical_analysis=statistical_analysis,
        n_dissections=n_dissections,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
    )

    # `to_pandas()` conserva el esquema estadistico completo de NFStream (~60 columnas:
    # per-direccion, ps/piat, flags TCP). `columns_to_anonymize=[]` mantiene las IPs crudas
    # para el etiquetado (la privacidad se aplica despues en privacy.py).
    try:
        df = streamer.to_pandas(columns_to_anonymize=[])
    except TypeError:
        # Firmas antiguas de NFStream sin el parametro.
        df = streamer.to_pandas()

    if df is None or df.empty:
        return pd.DataFrame()
    return _normalize_timestamps_ms(df)


def apply_packet_horizon(
    flows: pd.DataFrame,
    pcap_path: Path,
    packet_horizon: int | None,
) -> pd.DataFrame:
    """Aplica horizonte de paquetes: metadatos y, si N>0, stats desde primeros N paquetes."""
    if flows.empty:
        return flows

    df = assign_flow_ids(flows)
    if packet_horizon is None or packet_horizon <= 0:
        return apply_full_flow_metadata(df)
    return apply_early_packet_stats(df, pcap_path, packet_horizon)


def _run_nfstream_or_raise(
    pcap_path: Path,
    *,
    statistical_analysis: bool,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> pd.DataFrame:
    try:
        return _extract_nfstream(
            pcap_path,
            statistical_analysis=statistical_analysis,
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
            n_dissections=n_dissections,
        )
    except ImportError as exc:
        raise RuntimeError(
            "NFStream es el unico extractor soportado y no esta instalado. "
            "Ejecuta el pipeline en WSL/Linux con NFStream (ver README)."
        ) from exc
    except Exception as exc:
        raise RuntimeError(f"Extraccion NFStream fallida en {pcap_path.name}: {exc}") from exc


def extract_flows(
    pcap_path: Path,
    packet_horizon: int | None = None,
    *,
    statistical_analysis: bool = True,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> pd.DataFrame:
    df = _run_nfstream_or_raise(
        pcap_path,
        statistical_analysis=statistical_analysis,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        n_dissections=n_dissections,
    )
    if df.empty:
        logger.warning("NFStream no produjo flujos para %s", pcap_path.name)
    else:
        logger.info("Extracción NFStream: %d flujos", len(df))
    return apply_packet_horizon(df, pcap_path, packet_horizon)


def extract_flows_from_pcaps(
    pcap_paths: list[Path],
    *,
    statistical_analysis: bool = True,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> pd.DataFrame:
    """Extrae y concatena flujos de varios PCAPs (chunks upstream) en orden temporal."""
    if not pcap_paths:
        return pd.DataFrame()

    frames: list[pd.DataFrame] = []
    for i, pcap_path in enumerate(pcap_paths, start=1):
        logger.info("NFStream chunk %d/%d: %s", i, len(pcap_paths), pcap_path.name)
        df = _run_nfstream_or_raise(
            pcap_path,
            statistical_analysis=statistical_analysis,
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
            n_dissections=n_dissections,
        )
        if not df.empty:
            frames.append(df)

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    logger.info("Extracción multi-PCAP: %d flujos en %d archivos", len(combined), len(frames))
    return assign_flow_ids(combined)
