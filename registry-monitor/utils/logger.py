"""Logging, alerting, and CSV export utilities for monitoring events."""

from __future__ import annotations

import csv
import datetime as dt
import os
from typing import Any, Dict, Iterable

try:
    from colorama import Fore, Style, init as color_init

    color_init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False


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


def log_event(event: Dict[str, Any], log_file: str = "logs/registry_log.txt") -> str:
    """Persist one event to log file and return the written line."""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    line = format_log_line(event)
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(line + "\n")
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


def export_events_to_csv(
    events: Iterable[Dict[str, Any]],
    output_file: str = "logs/registry_log.csv",
) -> str:
    """Export collected events to CSV for offline analysis."""
    rows = list(events)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
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
    return output_file

