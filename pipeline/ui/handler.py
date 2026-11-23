"""Handler de logging que alimenta el buffer de la consola TUI."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.ui.logs import LogBuffer


class _PipelineNamespaceFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name == "pipeline" or record.name.startswith("pipeline.")


class UiQueueHandler(logging.Handler):
    """Encola líneas del namespace ``pipeline`` hacia un :class:`LogBuffer`."""

    def __init__(self, buffer: LogBuffer) -> None:
        super().__init__()
        self.buffer = buffer
        self.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        self.addFilter(_PipelineNamespaceFilter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            raw = self.format(record)
            message = record.getMessage()
            self.buffer.push(levelno=record.levelno, message=message, raw=raw)
        except Exception:
            self.handleError(record)


def attach_pipeline_logging(
    buffer: LogBuffer,
    *,
    verbose: bool = False,
) -> tuple[UiQueueHandler, int]:
    """Configura logging como el CLI y devuelve handler + nivel previo del root."""
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    prev_level = root.level
    root.setLevel(level)
    if not any(isinstance(h, UiQueueHandler) for h in root.handlers):
        if not root.handlers:
            logging.basicConfig(level=level, format="%(levelname)s %(message)s", force=True)

    handler = UiQueueHandler(buffer)
    handler.setLevel(level)
    root.addHandler(handler)
    return handler, prev_level


def detach_pipeline_logging(handler: UiQueueHandler, prev_root_level: int) -> None:
    root = logging.getLogger()
    root.removeHandler(handler)
    logging.getLogger().setLevel(prev_root_level)