"""Convierte metadatos JSON de la capa upstream al contrato de ingesta."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

CSV_VERSION = "1.0"
CSV_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

CSV_COLUMNS = [
    "row_id",
    "experiment_id",
    "run_id",
    "absolute_timestamp",
    "relative_timestamp_s",
    "event_kind",
    "source_node",
    "source_ip",
    "source_mac",
    "target_node",
    "target_ip",
    "target_mac",
    "protocol",
    "action",
    "label",
    "sublabel",
    "category",
    "subcategory",
    "mitre_ref",
    "mitre_technique",
    "mitre_subtechnique",
    "attack_intensity",
    "benign_profile",
    "tool",
    "duration_s",
    "notes",
    "row_checksum",
    "event_id",
    "scenario_id",
]


def _parse_started_at(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_scheduled_dt(value: str, *, assume_tz: str = "America/Santiago") -> datetime:
    """Parsea ``scheduled_dt`` (p. ej. ``27/07/2026 17:42:03``) a UTC.

    Upstream entrega fecha/hora de inicio del evento; si no trae zona, se asume
    America/Santiago (testbed doméstico Chile).
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("scheduled_dt vacío")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            from zoneinfo import ZoneInfo

            dt = dt.replace(tzinfo=ZoneInfo(assume_tz))
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            naive = datetime.strptime(raw, fmt)
            from zoneinfo import ZoneInfo

            return naive.replace(tzinfo=ZoneInfo(assume_tz)).astimezone(timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"No se pudo parsear scheduled_dt: {raw!r}")


def _event_absolute_timestamp(event: dict, started_at: datetime) -> tuple[datetime, float]:
    """Resuelve inicio: absolute_timestamp > offset_s > scheduled_dt > started_at."""
    abs_raw = event.get("absolute_timestamp")
    if abs_raw not in (None, ""):
        abs_dt = _parse_started_at(str(abs_raw))
        return abs_dt, (abs_dt - started_at).total_seconds()

    off_raw = event.get("offset_s")
    if off_raw not in (None, ""):
        offset_s = float(off_raw)
        return started_at + timedelta(seconds=offset_s), offset_s

    sched_raw = event.get("scheduled_dt")
    if sched_raw not in (None, ""):
        abs_dt = _parse_scheduled_dt(str(sched_raw))
        return abs_dt, (abs_dt - started_at).total_seconds()

    return started_at, 0.0


def _normalize_duration_s(raw) -> float:
    """``duration_s=0`` = ataque singular o benigno corto (semántica upstream).

    Downstream aplica ventana mínima de 1 s para el solape temporal.
    """
    try:
        value = float(raw if raw is not None else 0.0)
    except (TypeError, ValueError):
        value = 0.0
    return value if value > 0 else 1.0


def _infer_run_id(pcap_path: Path | None, payload: dict) -> str:
    if pcap_path is not None:
        stem = pcap_path.stem
        match = re.search(r"(\d{8}_\d{6})", stem)
        if match:
            return match.group(1)
    finished = payload.get("finished_at") or payload.get("started_at") or ""
    if finished:
        try:
            dt = _parse_started_at(str(finished))
            return dt.strftime("%Y%m%d_%H%M%S")
        except ValueError:
            pass
    return "run01"


def _format_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(CSV_DATE_FORMAT)


def _parse_mitre_ref(value: str) -> tuple[str, str]:
    """Descompone T1498.001 en técnica y sub-técnica MITRE."""
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if "." in raw:
        technique, sub = raw.split(".", 1)
        return technique, sub
    return raw, ""


def _stable_event_id(event: dict, index: int, run_id: str) -> str:
    existing = str(event.get("event_id", "")).strip()
    if existing:
        return existing
    key = (
        f"{run_id}|{index}|{event.get('offset_s')}|{event.get('action')}|"
        f"{event.get('source', event.get('source_ip', ''))}|"
        f"{event.get('target', event.get('target_ip', ''))}|{event.get('event_type', '')}"
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def resolve_pcap_paths_from_artifacts(
    payload: dict,
    base_dir: Path | None = None,
) -> list[Path]:
    """Resuelve rutas PCAP desde ``artifacts[]`` relativas a *base_dir*."""
    artifacts = payload.get("artifacts") or []
    pcaps: list[Path] = []
    for item in artifacts:
        if str(item.get("type", "")).upper() != "PCAP":
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        rel = str(item.get("path", name)).replace("\\", "/")
        rel_name = Path(rel).name
        if base_dir is not None:
            candidate = base_dir / rel_name
            if candidate.exists():
                pcaps.append(candidate)
                continue
        pcaps.append(Path(name))
    return pcaps


def _sort_pcap_name(name: str) -> tuple[int, int]:
    """Orden: archivo sin _part primero (0), luego part1, part2, ..."""
    match = re.search(r"_part(\d+)", name, re.IGNORECASE)
    if match:
        return (1, int(match.group(1)))
    return (0, 0)


def _prefer_part_pcaps(paths: list[Path]) -> list[Path]:
    """Identidad: no descartar el PCAP sin sufijo ``_partN``.

    En dumps reales el archivo ``{run}.pcap`` suele ser el *primer segmento*
    (no un merge duplicado de las parts). Omitirlo dejaba fuera el inicio del
    escenario y generaba eventos huérfanos. Upstream debe listar en
    ``artifacts[]`` todos los segmentos a consumir, en orden.
    """
    return paths


def ordered_pcap_paths(payload: dict, base_dir: Path) -> list[Path]:
    """PCAPs de ``artifacts[]`` en *base_dir*, ordenados (``_partN`` por número)."""
    paths = resolve_pcap_paths_from_artifacts(payload, base_dir=base_dir)
    existing = [p for p in paths if p.exists()]
    missing = [p.name for p in paths if not p.exists()]
    if missing:
        preview = ", ".join(missing[:5])
        raise FileNotFoundError(f"PCAPs no encontrados en {base_dir}: {preview}...")
    preferred = _prefer_part_pcaps(existing)
    # Sin _part van primero (segmento inicial), luego part1, part2, ...
    return sorted(preferred, key=lambda p: _sort_pcap_name(p.name))


def json_to_events_dataframe(
    payload: dict,
    pcap_path: Path | None = None,
) -> pd.DataFrame:
    """Parsea JSON upstream a DataFrame compatible con ``pipeline.ingest``."""
    if "started_at" not in payload:
        raise ValueError("JSON upstream debe incluir 'started_at'")

    started_at = _parse_started_at(str(payload["started_at"]))
    experiment_id = str(payload.get("experiment_id", pcap_path.stem if pcap_path else "exp"))
    run_id = _infer_run_id(pcap_path, payload)
    scenario_id = str(payload.get("scenario_id", "") or payload.get("experiment_id", ""))

    rows: list[dict] = []
    for i, event in enumerate(payload.get("events", []), start=1):
        abs_dt, offset_s = _event_absolute_timestamp(event, started_at)

        mitre_ref = str(
            event.get("mitre_ref")
            or event.get("mitre_technique", "")
            or ""
        ).strip()
        mitre_technique = str(event.get("mitre_technique", "")).strip()
        mitre_subtechnique = str(event.get("mitre_subtechnique", "")).strip()
        if mitre_ref and not mitre_technique:
            mitre_technique, mitre_subtechnique = _parse_mitre_ref(mitre_ref)

        rows.append({
            "row_id": i,
            "experiment_id": experiment_id,
            "run_id": run_id,
            "absolute_timestamp": _format_ts(abs_dt),
            "relative_timestamp_s": offset_s,
            "event_kind": str(event.get("event_type", event.get("event_kind", ""))),
            "source_node": str(event.get("source_node", "")),
            "source_ip": str(event.get("source_ip", event.get("source", ""))),
            "source_mac": str(event.get("source_mac", "")),
            "target_node": str(event.get("target_node", "")),
            "target_ip": str(event.get("target_ip", event.get("target", ""))),
            "target_mac": str(event.get("target_mac", "")),
            "protocol": str(event.get("protocol", "")),
            "action": str(event.get("action", "")),
            "label": str(event.get("label", "")),
            "sublabel": str(event.get("sublabel", "")),
            "category": str(event.get("category", "")),
            "subcategory": str(event.get("subcategory", "")),
            "mitre_ref": mitre_ref,
            "mitre_technique": mitre_technique,
            "mitre_subtechnique": mitre_subtechnique,
            "attack_intensity": str(event.get("attack_intensity", "")),
            "benign_profile": str(event.get("benign_profile", "")),
            "tool": str(event.get("tool", "")),
            "duration_s": _normalize_duration_s(event.get("duration_s")),
            "notes": str(event.get("notes", "")),
            "row_checksum": str(event.get("row_checksum", "")),
            "event_id": _stable_event_id(event, i, run_id),
            "scenario_id": str(event.get("scenario_id", scenario_id)),
        })

    if not rows:
        raise ValueError("Sin eventos en metadatos JSON upstream")

    df = pd.DataFrame(rows)
    df["experiment_id"] = df["experiment_id"].astype(str)
    df["run_id"] = df["run_id"].astype(str)
    return df


def _header_lines(payload: dict, pcap_path: Path | None) -> list[str]:
    started = payload.get("started_at", "")
    pcap_name = pcap_path.name if pcap_path else ""
    return [
        "# SH-DATASET metadata export (auxiliar — contrato oficial: JSON)",
        f"# csv_version: {CSV_VERSION}",
        "# schema_version: 1.0",
        f"# experiment_id: {payload.get('experiment_id', '')}",
        f"# environment: {payload.get('environment', '')}",
        f"# scenario_id: {payload.get('scenario_id', '')}",
        f"# start_time: {started}",
        f"# planned_duration_s: {payload.get('planned_duration_s', 0)}",
        f"# pcap_file: {pcap_name}",
        f"# orchestrator_version: {payload.get('orchestrator_version', '1.0.0')}",
    ]


def convert_upstream_json_to_csv(
    json_path: str | Path,
    pcap_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Exporta JSON upstream a CSV auxiliar compatible con ``pipeline.ingest``."""
    json_file = Path(json_path)
    pcap_file = Path(pcap_path)
    out_file = Path(output_path)

    if not json_file.exists():
        raise FileNotFoundError(f"Metadatos JSON no encontrados: {json_file}")
    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP no encontrado: {pcap_file}")

    payload = json.loads(json_file.read_text(encoding="utf-8"))
    df = json_to_events_dataframe(payload, pcap_file)

    lines = _header_lines(payload, pcap_file)
    export_cols = [c for c in CSV_COLUMNS if c in df.columns]
    lines.append(",".join(export_cols))
    for _, row in df.iterrows():
        lines.append(",".join(str(row[col]) for col in export_cols))

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_file
