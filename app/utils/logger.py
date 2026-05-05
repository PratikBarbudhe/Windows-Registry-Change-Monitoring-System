"""Logging, alerting, and CSV export utilities for monitoring events."""

from __future__ import annotations

import csv
import datetime as dt
import logging
from pathlib import Path
from typing import Any, Dict, Iterable

try:
    from colorama import Fore, Style, init as color_init

    color_init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False


def setup_logger(log_file: Path) -> logging.Logger:
    """Create a centralized logger with consistent console/file formatting."""
    logger = logging.getLogger("registry_monitor")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    log_file.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def _safe_text(value: Any) -> str:
    """Convert any value into display-safe text for logs and reports."""
    if value is None:
        return "None"
    return str(value).replace("\n", "\\n")


def format_log_line(event: Dict[str, Any]) -> str:
    """Format event into standard log line representation."""
    timestamp = event.get("timestamp", dt.datetime.now().isoformat())
    event_type = event.get("type", "INFO")
    severity = event.get("severity", "LOW")
    key = event.get("path", "UnknownKey")
    old_value = _safe_text(event.get("old_value"))
    new_value = _safe_text(event.get("new_value"))
    return f"[{timestamp}] [{event_type}] [{severity}] {key} | {old_value} -> {new_value}"


def log_event(event: Dict[str, Any], log_file: Path, logger: logging.Logger | None = None) -> str:
    """Persist one event to log file and return the written line."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    line = format_log_line(event)
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(line + "\n")
    if logger is not None:
        logger.info(line)
    return line


def print_alert(event: Dict[str, Any]) -> None:
    """Print console alert and highlight HIGH severity findings."""
    line = format_log_line(event)
    if COLOR_ENABLED and event.get("severity") == "HIGH":
        print(Fore.RED + line + Style.RESET_ALL)
    elif COLOR_ENABLED and event.get("severity") == "MEDIUM":
        print(Fore.YELLOW + line + Style.RESET_ALL)
    else:
        print(line)


def export_events_to_csv(events: Iterable[Dict[str, Any]], output_file: Path) -> str:
    """Export collected events to CSV for offline analysis."""
    rows = list(events)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "type",
                "severity",
                "category",
                "path",
                "value_name",
                "old_value",
                "new_value",
                "reason",
            ],
        )
        writer.writeheader()
        for event in rows:
            writer.writerow(
                {
                    "timestamp": event.get("timestamp"),
                    "type": event.get("type"),
                    "severity": event.get("severity"),
                    "category": event.get("category"),
                    "path": event.get("path"),
                    "value_name": event.get("value_name"),
                    "old_value": _safe_text(event.get("old_value")),
                    "new_value": _safe_text(event.get("new_value")),
                    "reason": event.get("reason"),
                }
            )
    return str(output_file)

