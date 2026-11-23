"""Tests del buffer y filtros de la consola TUI (sin Textual ni PCAP)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from pipeline.ui.logs import (
    LogBuffer,
    LogFilter,
    LogLine,
    StageTracker,
    UiLogLevel,
    cycle_level_filter,
    default_stages_on,
    filtered_lines,
    level_from_logging,
    parse_stage,
    RUN_STAGES,
)


def test_parse_stage_from_cli_prefixes():
    assert parse_stage("[ingest] PCAP=foo  metadata=bar") == "ingest"
    assert parse_stage("[extract] NFStream sobre cap") == "extract"
    assert parse_stage("[label] Correlación temporal") == "label"
    assert parse_stage("[preprocess] clases=three-class") == "preprocess"
    assert parse_stage("[validate] leakage check") == "validate"
    assert parse_stage("sin prefijo") == "pipeline"


def test_level_from_logging():
    assert level_from_logging(logging.ERROR) == UiLogLevel.ERROR
    assert level_from_logging(logging.WARNING) == UiLogLevel.WARNING
    assert level_from_logging(logging.INFO) == UiLogLevel.INFO


def test_cycle_level_filter():
    assert cycle_level_filter(0) == 1
    assert cycle_level_filter(1) == 2
    assert cycle_level_filter(2) == 0


def test_buffer_capacity_eviction():
    buf = LogBuffer(capacity=3)
    for i in range(4):
        evicted = buf.push(levelno=logging.INFO, message=f"line {i}")
        if i == 0:
            assert not evicted
        if i == 3:
            assert evicted
    assert len(buf.lines) == 3
    assert buf.lines[0].text == "line 1"


def test_buffer_pause_resume():
    buf = LogBuffer()
    buf.pause()
    buf.push(levelno=logging.INFO, message="[ingest] a")
    buf.push(levelno=logging.INFO, message="[ingest] b")
    assert len(buf.lines) == 0
    assert buf.pending_count == 2
    n = buf.resume()
    assert n == 2
    assert len(buf.lines) == 2


def test_filter_by_stage_and_solo():
    now = datetime.now(timezone.utc)
    lines = [
        LogLine("ingest", UiLogLevel.INFO, "a", "a", now),
        LogLine("extract", UiLogLevel.INFO, "b", "b", now),
    ]
    stages = default_stages_on(RUN_STAGES)
    stages["ingest"] = False
    filt = LogFilter(stages_on=stages)
    out = filtered_lines(lines, filt)
    assert len(out) == 1
    assert out[0].stage == "extract"

    filt.solo_stage = "ingest"
    out_solo = filtered_lines(lines, filt)
    assert len(out_solo) == 1
    assert out_solo[0].stage == "ingest"


def test_filter_by_level_and_query():
    now = datetime.now(timezone.utc)
    lines = [
        LogLine("pipeline", UiLogLevel.INFO, "ok", "ok", now),
        LogLine("pipeline", UiLogLevel.WARNING, "warn", "warn", now),
        LogLine("pipeline", UiLogLevel.ERROR, "fail", "fail", now),
    ]
    filt = LogFilter(stages_on=default_stages_on(["pipeline"]), level_mode=1)
    assert len(filtered_lines(lines, filt)) == 1
    filt.level_mode = 2
    assert len(filtered_lines(lines, filt)) == 2
    filt.level_mode = 0
    filt.query = "fail"
    assert len(filtered_lines(lines, filt)) == 1


def test_stage_tracker_advances_on_new_stage():
    now = datetime.now(timezone.utc)
    tr = StageTracker(RUN_STAGES)
    assert tr.status("ingest") == "running"
    tr.observe(LogLine("extract", UiLogLevel.INFO, "[extract] x", "x", now))
    assert tr.status("ingest") == "done"
    assert tr.status("extract") == "running"


def test_stage_tracker_error():
    now = datetime.now(timezone.utc)
    tr = StageTracker(RUN_STAGES)
    tr.observe(LogLine("label", UiLogLevel.ERROR, "[label] fail", "fail", now))
    assert tr.status("label") == "error"