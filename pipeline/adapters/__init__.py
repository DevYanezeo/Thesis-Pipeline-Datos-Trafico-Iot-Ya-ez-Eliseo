"""Adaptadores de artefactos upstream al contrato de ingesta downstream."""

from pipeline.adapters.upstream_metadata_json import convert_upstream_json_to_csv

__all__ = ["convert_upstream_json_to_csv"]
