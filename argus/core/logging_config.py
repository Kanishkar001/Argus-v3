"""
argus.core.logging_config
~~~~~~~~~~~~~~~~~~~~~~~~~~
Unified logging configuration for the entire Argus framework.

Call ``setup_logging()`` once at startup (in ``__main__.py`` or CLI bootstrap).
Modules obtain their loggers via ``logging.getLogger("argus.modules.<name>")``.

Two handlers are configured:
  • **Console** – Rich-formatted coloured output (respects log level).
  • **File**    – JSON-lines structured log for post-run analysis.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from argus.config.settings import LOG_SETTINGS


# ── JSON formatter for file handler ──────────────────────────────────────────

class _JSONFormatter(logging.Formatter):
    """Emit one JSON object per log record (newline-delimited)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# ── Rich console handler (lazy import to avoid hard dep if Rich absent) ──────

def _make_console_handler(level: int) -> logging.Handler:
    try:
        from rich.logging import RichHandler
        handler = RichHandler(
            level=level,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
        )
    except ImportError:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "[%(levelname)s] %(name)s – %(message)s"
        ))
        handler.setLevel(level)
    return handler


# ── Public API ───────────────────────────────────────────────────────────────

_CONFIGURED = False


def setup_logging(
    console_level: str | None = None,
    log_file: str | None = None,
    file_level: str = "DEBUG",
) -> None:
    """Initialise Argus-wide logging.  Safe to call more than once (no-op)."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    enabled = LOG_SETTINGS.get("enable_logging", True)
    if not enabled:
        logging.disable(logging.CRITICAL)
        return

    level_name = (console_level or LOG_SETTINGS.get("log_level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger("argus")
    root.setLevel(logging.DEBUG)  # let handlers decide

    # Console
    root.addHandler(_make_console_handler(level))

    # File
    target_file = log_file or LOG_SETTINGS.get("log_file", "argus.log")
    if target_file:
        try:
            Path(target_file).parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(target_file, encoding="utf-8")
            fh.setLevel(getattr(logging, file_level.upper(), logging.DEBUG))
            fh.setFormatter(_JSONFormatter())
            root.addHandler(fh)
        except OSError:
            pass  # non-fatal: file logging is nice-to-have


def get_module_logger(module_name: str) -> logging.Logger:
    """Return a child logger under the ``argus.modules`` namespace."""
    return logging.getLogger(f"argus.modules.{module_name}")
