"""Punto de entrada CLI del pipeline de datos IoT."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from pipeline.adapters.upstream_metadata_json import (
    convert_upstream_json_to_csv,
    ordered_pcap_paths,
)
from pipeline.early_packets import apply_early_packet_stats, apply_full_flow_metadata
from pipeline.evaluate import evaluate_io, metrics_to_dict
from pipeline.extract import (
    DEFAULT_ACTIVE_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_N_DISSECTIONS,
    extract_flows,
    extract_flows_from_pcaps,
)
from pipeline.flow_ids import assign_flow_ids
from pipeline.ingest import ingest
from pipeline.label import compute_labeling_stats, label_flows
from pipeline.persist import write_outputs
from pipeline.privacy import PrivacyMode, apply_privacy
from pipeline.traceability import evaluate_traceability

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_INGEST = 2
EXIT_EXTRACT = 3
EXIT_LABEL = 4
EXIT_PERSIST = 5
EXIT_CONVERT = 6
EXIT_PREPROCESS = 7
EXIT_VALIDATION = 8

logger = logging.getLogger(__name__)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


def _validate_horizons(values: list[int]) -> list[int]:
    if not values:
        raise ValueError("Debe indicar al menos un horizonte N positivo")
    if any(n <= 0 for n in values):
        raise ValueError("Los horizontes deben ser enteros positivos")
    if len(values) != len(set(values)):
        raise ValueError("Los horizontes no pueden repetirse")
    for prev, curr in zip(values, values[1:]):
        if curr <= prev:
            raise ValueError(
                f"Los horizontes deben ser estrictamente crecientes (ej. 5,10,20); "
                f"encontrado {prev} seguido de {curr}"
            )
    return values


def _parse_horizons(
    single: int | None,
    multi: str | None,
    *,
    include_full: bool,
) -> list[int | None]:
    if multi:
        values = _validate_horizons([int(x.strip()) for x in multi.split(",") if x.strip()])
        return ([None] + values) if include_full else values
    if single is not None:
        if single <= 0:
            raise ValueError("--packet-horizon debe ser un entero positivo")
        return [None, single] if include_full else [single]
    return [None]


def _extract_base_flows(
    pcap: Path,
    *,
    statistical_analysis: bool,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> Any:
    """NFStream una sola vez; sin horizonte (full flow features)."""
    df = extract_flows(
        pcap,
        packet_horizon=None,
        statistical_analysis=statistical_analysis,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        n_dissections=n_dissections,
    )
    if df.empty:
        return df
    return assign_flow_ids(df)


def _scenario_id_for_flows(ingested, flows) -> str:
    if ingested.scenario_id:
        return ingested.scenario_id
    if "scenario_id" in ingested.metadata.columns:
        vals = ingested.metadata["scenario_id"].astype(str).replace("", pd.NA).dropna()
        if not vals.empty:
            return str(vals.iloc[0])
    return str(ingested.experiment_id)


def _prepare_labeled(ingested, flows):
    scenario = _scenario_id_for_flows(ingested, flows)
    if "scenario_id" not in flows.columns or flows["scenario_id"].astype(str).eq("").all():
        flows = flows.copy()
        flows["scenario_id"] = scenario
    labeled = label_flows(flows, ingested.metadata, ingested.capture_started_at)
    if "scenario_id" not in labeled.columns or labeled["scenario_id"].astype(str).eq("").all():
        labeled["scenario_id"] = scenario
    return labeled, compute_labeling_stats(labeled)


def _persist_variant(
    labeled_full,
    stats,
    trace,
    ingested,
    metadata,
    output,
    pcap,
    packet_horizon,
    io_evaluate: bool,
    privacy_mode: PrivacyMode,
    *,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> dict[str, Any]:
    if packet_horizon is None:
        variant = apply_full_flow_metadata(labeled_full.copy())
    else:
        variant = apply_early_packet_stats(labeled_full.copy(), pcap, packet_horizon)

    variant = apply_privacy(variant, privacy_mode)

    paths = write_outputs(
        variant,
        output,
        ingested.experiment_id,
        ingested.run_id,
        ingested.pcap_path,
        metadata,
        labeling_stats=stats,
        metadata_format=ingested.metadata_format,
        scenario_id=_scenario_id_for_flows(ingested, variant),
        packet_horizon=packet_horizon,
        traceability_metrics=trace.to_dict(),
        write_manifest=False,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        n_dissections=n_dissections,
    )

    entry: dict[str, Any] = {
        "packet_horizon_n": packet_horizon,
        "extraction_mode": variant["extraction_mode"].iloc[0] if not variant.empty else "full_flow",
        "parquet": paths["parquet"].name,
        "csv_baseline": paths["csv"].name,
        "flow_count": len(variant),
    }

    if io_evaluate:
        metrics = evaluate_io(paths["csv"], paths["parquet"])
        suffix = f"_n{packet_horizon}" if packet_horizon else ""
        metrics_path = output / f"io_metrics{suffix}.json"
        metrics_path.write_text(json.dumps(metrics_to_dict(metrics), indent=2), encoding="utf-8")
        entry["io_metrics"] = metrics_path.name
        logger.info(
            "  -> I/O [%s]: compresión %sx, speedup %sx",
            entry["extraction_mode"],
            metrics.compression_ratio,
            metrics.read_speedup,
        )
    return entry


def run_pipeline(
    pcap: Path | None,
    metadata: Path,
    output: Path,
    evaluate: bool,
    packet_horizon: int | None,
    packet_horizons: str | None,
    *,
    include_full: bool,
    statistical_analysis: bool,
    privacy_mode: PrivacyMode,
    artifact_pcap_dir: Path | None = None,
    idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
    active_timeout: int = DEFAULT_ACTIVE_TIMEOUT,
    n_dissections: int = DEFAULT_N_DISSECTIONS,
) -> int:
    if idle_timeout <= 0 or active_timeout <= 0 or n_dissections < 0:
        logger.error(
            "Timeouts NFStream deben ser > 0 y n_dissections >= 0 "
            "(idle=%s active=%s n_dissections=%s)",
            idle_timeout,
            active_timeout,
            n_dissections,
        )
        return EXIT_USAGE

    try:
        horizons = _parse_horizons(packet_horizon, packet_horizons, include_full=include_full)
    except ValueError as exc:
        logger.error("%s", exc)
        return EXIT_USAGE

    pcap_paths: list[Path]
    if artifact_pcap_dir is not None:
        try:
            payload = json.loads(metadata.read_text(encoding="utf-8"))
            pcap_paths = ordered_pcap_paths(payload, artifact_pcap_dir)
            pcap = pcap_paths[0]
            logger.info(
                "[ingest] %d PCAPs desde artifacts[] en %s",
                len(pcap_paths),
                artifact_pcap_dir,
            )
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Resolución de artifacts PCAP fallida: %s", exc)
            return EXIT_INGEST
    elif pcap is not None:
        pcap_paths = [pcap]
    else:
        logger.error("Indique --pcap o --artifact-pcap-dir")
        return EXIT_USAGE

    try:
        logger.info("[ingest] PCAP=%s  metadata=%s", pcap.name, metadata.name)
        ingested = ingest(pcap, metadata)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("Ingesta fallida: %s", exc)
        return EXIT_INGEST

    try:
        if len(pcap_paths) > 1:
            logger.info(
                "[extract] NFStream multi-PCAP (%d chunks, statistical_analysis=%s)...",
                len(pcap_paths),
                statistical_analysis,
            )
            flows = extract_flows_from_pcaps(
                pcap_paths,
                statistical_analysis=statistical_analysis,
                idle_timeout=idle_timeout,
                active_timeout=active_timeout,
                n_dissections=n_dissections,
            )
        else:
            logger.info(
                "[extract] NFStream sobre %s (statistical_analysis=%s)...",
                pcap.name,
                statistical_analysis,
            )
            flows = _extract_base_flows(
                ingested.pcap_path,
                statistical_analysis=statistical_analysis,
                idle_timeout=idle_timeout,
                active_timeout=active_timeout,
                n_dissections=n_dissections,
            )
        if flows.empty:
            logger.error("No se extrajeron flujos del PCAP")
            return EXIT_EXTRACT
        logger.info("  -> %d flujos extraídos", len(flows))
    except RuntimeError as exc:
        logger.error("Extracción fallida: %s", exc)
        return EXIT_EXTRACT

    pcap_for_horizons: Path | list[Path] = pcap_paths if len(pcap_paths) > 1 else pcap_paths[0]

    try:
        logger.info("[label] Correlación temporal evento↔flujo...")
        labeled_full, stats = _prepare_labeled(ingested, flows)
        trace = evaluate_traceability(labeled_full, ingested.metadata, stats)
        logger.info(
            "  -> attack=%d benign=%d background=%d",
            stats.attack_flows,
            stats.benign_flows,
            stats.background_flows,
        )
    except Exception as exc:
        logger.error("Etiquetado fallido: %s", exc)
        return EXIT_LABEL

    output.mkdir(parents=True, exist_ok=True)
    trace_path = output / "traceability_report.json"
    trace_path.write_text(json.dumps(trace.to_dict(), indent=2), encoding="utf-8")

    try:
        logger.info("[persist] Escribiendo variantes en %s...", output)
        dataset_entries: list[dict[str, Any]] = []
        for horizon in horizons:
            label = "full_flow" if horizon is None else f"first_{horizon}_packets"
            logger.info("  -> variante %s", label)
            entry = _persist_variant(
                labeled_full,
                stats,
                trace,
                ingested,
                metadata,
                output,
                pcap_for_horizons,
                horizon,
                evaluate,
                privacy_mode,
                idle_timeout=idle_timeout,
                active_timeout=active_timeout,
                n_dissections=n_dissections,
            )
            dataset_entries.append(entry)

        master_manifest = {
            "schema_version": "1.2",
            "experiment_id": ingested.experiment_id,
            "run_id": ingested.run_id,
            "metadata_format": ingested.metadata_format,
            "source_pcap": str(ingested.pcap_path),
            "source_pcap_chunks": [str(p) for p in pcap_paths] if len(pcap_paths) > 1 else None,
            "source_metadata": str(metadata),
            "traceability_report": trace_path.name,
            "datasets": dataset_entries,
            "labeling_stats": stats.to_dict(),
            "traceability_metrics": trace.to_dict(),
            "statistical_analysis": statistical_analysis,
            "privacy_mode": privacy_mode,
            "include_full_flow": include_full,
            "packet_horizons": horizons,
            "nfstream_timeouts": {
                "idle_timeout_s": idle_timeout,
                "active_timeout_s": active_timeout,
                "n_dissections": n_dissections,
            },
        }
        (output / "manifest.json").write_text(
            json.dumps(master_manifest, indent=2),
            encoding="utf-8",
        )
        logger.info("  -> manifest.json, %s", trace_path.name)
    except Exception as exc:
        logger.error("Persistencia fallida: %s", exc)
        return EXIT_PERSIST

    return EXIT_OK


def run_preprocess_ml(
    input_path: Path,
    output: Path,
    *,
    test_size: float,
    split_by: str,
    stratify: bool,
    seed: int,
    classes: str,
    scaler: str,
    benchmark: bool,
) -> int:
    # Import perezoso: mantiene el resto del CLI usable sin scikit-learn/joblib.
    try:
        from pipeline.benchmark_qa import benchmark_qa
        from pipeline.benchmark_qa import write_report as write_benchmark_report
        from pipeline.preprocess import preprocess_dataset
        from pipeline.preprocess import write_outputs as write_ml_outputs
        from pipeline.validate_ml import validate_processed
        from pipeline.validate_ml import write_report as write_validation_report
    except ImportError as exc:
        logger.error("Faltan dependencias de preprocesamiento (scikit-learn/joblib): %s", exc)
        return EXIT_PREPROCESS

    if not input_path.exists():
        logger.error("No existe el dataset de entrada: %s", input_path)
        return EXIT_USAGE

    try:
        flows = pd.read_parquet(input_path)
    except Exception as exc:
        logger.error("No se pudo leer el Parquet de entrada: %s", exc)
        return EXIT_PREPROCESS

    if flows.empty:
        logger.error("El dataset de entrada esta vacio")
        return EXIT_PREPROCESS

    try:
        logger.info(
            "[preprocess] clases=%s split_by=%s test_size=%s stratify=%s scaler=%s seed=%d",
            classes,
            split_by,
            test_size,
            stratify,
            scaler,
            seed,
        )
        result = preprocess_dataset(
            flows,
            test_size=test_size,
            split_by=split_by,
            stratify=stratify,
            seed=seed,
            classes=classes,
            scaler=scaler,
            source=str(input_path),
        )
    except ValueError as exc:
        logger.error("Preprocesamiento fallido: %s", exc)
        return EXIT_PREPROCESS

    paths = write_ml_outputs(result, output)
    logger.info(
        "  -> train=%d test=%d features=%d",
        len(result.train_processed),
        len(result.test_processed),
        len(result.feature_names_out),
    )
    for w in result.split_meta.get("warnings", []):
        logger.warning("  [split] %s", w)

    report = validate_processed(result.train_processed, result.test_processed, result.feature_manifest)
    report_path = write_validation_report(report, output)
    status = "OK" if report["passed"] else "FALLO"
    logger.info("  -> validacion anti-fuga: %s (%s)", status, report_path.name)
    for check in report["checks"]:
        if not check["passed"]:
            logger.warning("  [validate] %s: %s", check["name"], check["detail"])

    if benchmark:
        logger.info("[benchmark] QA de aprendibilidad (modelos ligeros)...")
        bench = benchmark_qa(result.train_processed, result.test_processed, seed=seed)
        bench_path = write_benchmark_report(bench, output)
        for name, m in bench["models"].items():
            if "error" in m:
                logger.warning("  [qa] %s: %s", name, m["error"])
            else:
                logger.info(
                    "  -> %s: MCC=%.3f BACC=%.3f F1m=%.3f",
                    name,
                    m["mcc"],
                    m["balanced_accuracy"],
                    m["f1_macro"],
                )
        logger.info("  -> %s", bench_path.name)

    logger.info(
        "[preprocess] Paquete handoff en %s: %s",
        output,
        ", ".join(p.name for p in paths.values()),
    )

    return EXIT_OK if report["passed"] else EXIT_VALIDATION


def run_convert_metadata(json_path: Path, pcap_path: Path, output: Path) -> int:
    try:
        out = convert_upstream_json_to_csv(json_path, pcap_path, output)
        logger.info("CSV auxiliar generado: %s", out)
        return EXIT_OK
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        logger.error("Conversión fallida: %s", exc)
        return EXIT_CONVERT


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pipeline de datos IoT: PCAP + metadatos JSON → Parquet etiquetado",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Ejecutar pipeline completo")
    run_p.add_argument("-v", "--verbose", action="store_true", help="Log detallado")
    run_p.add_argument("--pcap", default=None, help="Ruta al archivo .pcap (o use --artifact-pcap-dir)")
    run_p.add_argument(
        "--artifact-pcap-dir",
        default=None,
        help="Directorio con PCAPs listados en metadata.json artifacts[] (chunks upstream)",
    )
    run_p.add_argument(
        "--metadata",
        required=True,
        help="Ruta a metadatos JSON (contrato oficial) o CSV (auxiliar)",
    )
    run_p.add_argument("--output", required=True, help="Directorio de salida")
    run_p.add_argument("--evaluate", action="store_true", help="Calcular métricas I/O y consultas")
    run_p.add_argument(
        "--packet-horizon",
        type=int,
        default=None,
        help="Un solo horizonte N (por defecto no genera full_flow salvo --full)",
    )
    run_p.add_argument(
        "--packet-horizons",
        type=str,
        default=None,
        help=(
            "Lista de horizontes N elegida por el investigador (ej: 5,10,20); "
            "no hay lista fija de producto. Por defecto no genera full_flow salvo --full"
        ),
    )
    run_p.add_argument(
        "--full",
        action="store_true",
        help="Incluir variante full_flow además de los horizontes N solicitados",
    )
    run_p.add_argument(
        "--idle-timeout",
        type=int,
        default=DEFAULT_IDLE_TIMEOUT,
        help=f"Timeout idle NFStream en segundos (default piloto: {DEFAULT_IDLE_TIMEOUT})",
    )
    run_p.add_argument(
        "--active-timeout",
        type=int,
        default=DEFAULT_ACTIVE_TIMEOUT,
        help=f"Timeout active NFStream en segundos (default piloto: {DEFAULT_ACTIVE_TIMEOUT})",
    )
    run_p.add_argument(
        "--n-dissections",
        type=int,
        default=DEFAULT_N_DISSECTIONS,
        help=f"n_dissections NFStream (default piloto: {DEFAULT_N_DISSECTIONS})",
    )
    run_p.add_argument(
        "--statistical-analysis",
        dest="statistical_analysis",
        action="store_true",
        default=True,
        help="NFStream con análisis estadístico extendido (por defecto: activado)",
    )
    run_p.add_argument(
        "--no-statistical-analysis",
        dest="statistical_analysis",
        action="store_false",
        help="NFStream sin análisis estadístico extendido (extracción más rápida)",
    )
    run_p.add_argument(
        "--privacy",
        choices=("none", "pseudonymize", "anonymize"),
        default="none",
        help="Privacidad en columnas IP de salida: none | pseudonymize | anonymize",
    )

    conv_p = sub.add_parser(
        "convert-metadata",
        help="Exportar JSON upstream a CSV auxiliar (no es el contrato principal)",
    )
    conv_p.add_argument("-v", "--verbose", action="store_true", help="Log detallado")
    conv_p.add_argument("--json", required=True, help="Ruta al JSON de metadatos upstream")
    conv_p.add_argument("--pcap", required=True, help="Ruta al PCAP asociado")
    conv_p.add_argument("--output", required=True, help="Ruta de salida .csv")

    prep_p = sub.add_parser(
        "preprocess-ml",
        help="Preprocesar flows.parquet a dataset train/test ML-ready sin fuga de datos",
    )
    prep_p.add_argument("-v", "--verbose", action="store_true", help="Log detallado")
    prep_p.add_argument("--input", required=True, help="Ruta a flows.parquet etiquetado")
    prep_p.add_argument("--output", required=True, help="Directorio de salida del paquete handoff")
    prep_p.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Proporcion de test: 0.2=80/20, 0.3=70/30 (default 0.2)",
    )
    prep_p.add_argument(
        "--split-by",
        choices=("episode", "temporal", "flow"),
        default="episode",
        help="Unidad del split: episode (default, anti-fuga) | temporal | flow (diagnostico)",
    )
    prep_p.add_argument(
        "--stratify",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Estratificar preservando la proporcion de clases (default: activado)",
    )
    prep_p.add_argument("--seed", type=int, default=42, help="Semilla de reproducibilidad (default 42)")
    prep_p.add_argument(
        "--classes",
        choices=("three-class", "attack-benign", "attack-vs-all"),
        default="three-class",
        help="Modo de clases: three-class | attack-benign | attack-vs-all",
    )
    prep_p.add_argument(
        "--scaler",
        choices=("robust", "standard"),
        default="robust",
        help="Escalador de numericas: robust (default, tolerante a outliers) | standard",
    )
    prep_p.add_argument(
        "--benchmark",
        action="store_true",
        help="Correr benchmark QA (MCC/BACC) para verificar aprendibilidad del dataset",
    )

    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", False))

    if args.command == "run":
        return run_pipeline(
            Path(args.pcap) if args.pcap else None,
            Path(args.metadata),
            Path(args.output),
            args.evaluate,
            args.packet_horizon,
            args.packet_horizons,
            include_full=args.full,
            statistical_analysis=args.statistical_analysis,
            privacy_mode=args.privacy,
            artifact_pcap_dir=Path(args.artifact_pcap_dir) if args.artifact_pcap_dir else None,
            idle_timeout=args.idle_timeout,
            active_timeout=args.active_timeout,
            n_dissections=args.n_dissections,
        )
    if args.command == "convert-metadata":
        return run_convert_metadata(
            Path(args.json),
            Path(args.pcap),
            Path(args.output),
        )
    if args.command == "preprocess-ml":
        return run_preprocess_ml(
            Path(args.input),
            Path(args.output),
            test_size=args.test_size,
            split_by=args.split_by,
            stratify=args.stratify,
            seed=args.seed,
            classes=args.classes,
            scaler=args.scaler,
            benchmark=args.benchmark,
        )
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
