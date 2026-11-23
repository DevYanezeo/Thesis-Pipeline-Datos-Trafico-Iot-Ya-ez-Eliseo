"""Tests del handler de logging hacia el buffer (sin Textual)."""
from __future__ import annotations

import logging

from pipeline.ui.handler import attach_pipeline_logging, detach_pipeline_logging
from pipeline.ui.logs import LogBuffer, parse_stage


def test_handler_captures_pipeline_cli_messages():
    buf = LogBuffer()
    handler, prev = attach_pipeline_logging(buf, verbose=False)
    try:
        log = logging.getLogger("pipeline.cli")
        log.info("[ingest] prueba handler")
        assert len(buf.lines) == 1
        assert buf.lines[0].stage == parse_stage("[ingest] prueba handler")
    finally:
        detach_pipeline_logging(handler, prev)