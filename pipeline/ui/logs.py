"""Buffer de logs, etapas y filtros para la consola TUI (sin dependencia de terminal)."""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Literal

CAPACITY = 10_000

STAGE_TAG_RE = re.compile(r"\[([a-zA-Z_]+)\]")

RUN_STAGES: tuple[str, ...] = ("ingest", "extract", "label", "persist", "pipeline")
PREPROCESS_STAGES: tuple[str, ...] = (
    "preprocess",
    "split",
    "validate",
    "benchmark",
    "qa",
    "pipeline",
)
CONVERT_STAGES: tuple[str, ...] = ("pipeline",)

StageStatus = Literal["pending", "running", "done", "error"]


class UiLogLevel(IntEnum):
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR


@dataclass(frozen=True)
class LogLine:
    stage: str
    level: UiLogLevel
    text: str
    raw: str
    at: datetime


@dataclass
class LogFilter:
    stages_on: dict[str, bool] = field(default_factory=dict)
    solo_stage: str | None = None
    level_mode: int = 0
    query: str = ""

    def clone(self) -> LogFilter:
        return LogFilter(
            stages_on=dict(self.stages_on),
            solo_stage=self.solo_stage,
            level_mode=self.level_mode,
            query=self.query,
        )


def level_from_logging(levelno: int) -> UiLogLevel:
    if levelno >= logging.ERROR:
        return UiLogLevel.ERROR
    if levelno >= logging.WARNING:
        return UiLogLevel.WARNING
    return UiLogLevel.INFO


def parse_stage(message: str) -> str:
    match = STAGE_TAG_RE.search(message)
    if match:
        return match.group(1).lower()
    return "pipeline"


def cycle_level_filter(current: int) -> int:
    if current == 0:
        return 1
    if current == 1:
        return 2
    return 0


def level_filter_label(mode: int) -> str:
    if mode == 1:
        return "ERR"
    if mode == 2:
        return "ERR+WRN"
    return "ALL"


def default_stages_on(stages: Sequence[str]) -> dict[str, bool]:
    return {s: True for s in stages}


class LogBuffer:
    def __init__(self, capacity: int = CAPACITY) -> None:
        self._capacity = capacity
        self._lines: list[LogLine] = []
        self._paused = False
        self._pending: list[LogLine] = []

    def push(
        self,
        *,
        levelno: int,
        message: str,
        raw: str | None = None,
        at: datetime | None = None,
    ) -> bool:
        stage = parse_stage(message)
        text = message.strip()
        line = LogLine(
            stage=stage,
            level=level_from_logging(levelno),
            text=text,
            raw=raw or text,
            at=at or datetime.now(timezone.utc),
        )
        if self._paused:
            self._pending.append(line)
            return False
        return self._append(line)

    def _append(self, line: LogLine) -> bool:
        evicted = False
        if len(self._lines) >= self._capacity:
            self._lines = self._lines[1:]
            evicted = True
        self._lines.append(line)
        return evicted

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> int:
        self._paused = False
        n = len(self._pending)
        for line in self._pending:
            self._append(line)
        self._pending.clear()
        return n

    @property
    def paused(self) -> bool:
        return self._paused

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def lines(self) -> list[LogLine]:
        return self._lines

    def clear(self) -> None:
        self._lines.clear()
        self._pending.clear()


def filtered_lines(lines: Iterable[LogLine], filt: LogFilter) -> list[LogLine]:
    query = filt.query.strip().lower()
    out: list[LogLine] = []
    for line in lines:
        if filt.solo_stage:
            if line.stage != filt.solo_stage:
                continue
        elif not filt.stages_on.get(line.stage, True):
            continue

        if filt.level_mode == 1 and line.level != UiLogLevel.ERROR:
            continue
        if filt.level_mode == 2 and line.level not in (UiLogLevel.ERROR, UiLogLevel.WARNING):
            continue

        if query:
            haystack = f"{line.stage} {line.text}".lower()
            if query not in haystack:
                continue
        out.append(line)
    return out


class StageTracker:
    """Estado de etapas inferido desde los prefijos [etapa] del logging existente."""

    def __init__(self, stage_order: Sequence[str]) -> None:
        self._order = tuple(stage_order)
        self._status: dict[str, StageStatus] = {s: "pending" for s in self._order}
        if self._order:
            self._status[self._order[0]] = "running"

    @property
    def order(self) -> tuple[str, ...]:
        return self._order

    def status(self, stage: str) -> StageStatus:
        return self._status.get(stage, "pending")

    def statuses(self) -> dict[str, StageStatus]:
        return dict(self._status)

    def observe(self, line: LogLine) -> None:
        stage = line.stage
        if stage not in self._status:
            return
        if line.level == UiLogLevel.ERROR and stage in self._status:
            self._status[stage] = "error"
            return
        idx = self._order.index(stage) if stage in self._order else -1
        if idx < 0:
            return
        self._status[stage] = "running"
        for i in range(idx):
            prev = self._order[i]
            if self._status.get(prev) not in ("error",):
                self._status[prev] = "done"

    def mark_complete(self, *, error_stage: str | None = None) -> None:
        if error_stage and error_stage in self._status:
            self._status[error_stage] = "error"
            return
        for stage in self._order:
            if self._status.get(stage) != "error":
                self._status[stage] = "done"