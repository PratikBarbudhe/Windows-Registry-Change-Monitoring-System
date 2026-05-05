"""Autorun entry analysis for persistence detection."""

from __future__ import annotations

import os
import shlex
from typing import Any, Dict, List


SUSPICIOUS_PATH_HINTS = [
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
]

TRUSTED_PREFIXES = [
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
]


def _extract_executable_path(command: str) -> str:
    """Extract executable path from registry command string."""
    if not command:
        return ""

    command = command.strip()
    try:
        parts = shlex.split(command, posix=False)
        return parts[0] if parts else ""
    except ValueError:
        return command.split(" ")[0]


def _is_unknown_executable(path: str) -> bool:
    """Return True when executable path does not match common trusted locations."""
    normalized = path.lower().strip('"')
    if not normalized:
        return False

    if not normalized.endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
        return True

    return not any(normalized.startswith(prefix) for prefix in TRUSTED_PREFIXES)


def evaluate_autorun_value(path: str, value_name: str, value_data: Any) -> Dict[str, Any]:
    """Evaluate one autorun value for suspicious persistence characteristics."""
    value_text = str(value_data or "")
    exe_path = _extract_executable_path(value_text)
    normalized = value_text.lower()

    reasons: List[str] = []
    severity = "LOW"

    if any(token in normalized for token in SUSPICIOUS_PATH_HINTS):
        reasons.append("Autorun path points to user-writable AppData/Temp location.")
        severity = "MEDIUM"

    if _is_unknown_executable(exe_path):
        reasons.append("Autorun command references unknown or non-standard executable.")
        severity = "HIGH" if severity == "MEDIUM" else "MEDIUM"

    return {
        "path": path,
        "value_name": value_name,
        "value_data": value_text,
        "executable_path": exe_path,
        "suspicious": bool(reasons),
        "severity": severity if reasons else "LOW",
        "reason": " | ".join(reasons) if reasons else "No suspicious autorun pattern detected.",
    }


def detect_autorun_changes(change_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter and analyze new/modified autorun entries from change events."""
    findings: List[Dict[str, Any]] = []
    for event in change_events:
        if event.get("type") not in {"VALUE_CREATED", "VALUE_MODIFIED"}:
            continue

        category = event.get("category", "").lower()
        if "autorun" not in category and "run" not in event.get("path", "").lower():
            continue

        findings.append(
            evaluate_autorun_value(
                event.get("path", ""),
                event.get("value_name", "(Unknown)"),
                event.get("new_value"),
            )
        )
    return findings

