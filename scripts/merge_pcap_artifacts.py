#!/usr/bin/env python3
"""Une PCAPs listados en metadata.json (principal + chunks) con mergecap."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from pipeline.adapters.upstream_metadata_json import ordered_pcap_paths, resolve_pcap_paths_from_artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge PCAP chunks from upstream metadata.json")
    parser.add_argument("--metadata", required=True, help="Ruta a metadata.json")
    parser.add_argument("--pcap-dir", required=True, help="Directorio con los archivos .pcap")
    parser.add_argument("--output", required=True, help="PCAP unificado de salida")
    args = parser.parse_args()

    meta_path = Path(args.metadata)
    base_dir = Path(args.pcap_dir)
    out_path = Path(args.output)

    payload = json.loads(meta_path.read_text(encoding="utf-8"))
    inputs = ordered_pcap_paths(payload, base_dir)
    if not inputs:
        print("No hay artefactos PCAP en metadata", file=sys.stderr)
        return 1

    if len(inputs) == 1:
        shutil.copy2(inputs[0], out_path)
        print(f"Un solo PCAP — copiado a {out_path}")
        return 0

    mergecap = shutil.which("mergecap")
    if mergecap is None:
        print("mergecap no encontrado (instalar wireshark-common en WSL)", file=sys.stderr)
        return 2

    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [mergecap, "-w", str(out_path), *[str(p) for p in inputs]]
    print(f"Uniendo {len(inputs)} PCAPs → {out_path}")
    subprocess.run(cmd, check=True)
    print(f"Listo: {out_path} ({out_path.stat().st_size / (1024**2):.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
