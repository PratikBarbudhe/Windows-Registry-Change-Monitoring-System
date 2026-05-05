"""Registry monitoring engine for change detection."""

from __future__ import annotations

import datetime as dt
import time
from typing import Any, Dict, Generator, List, Optional, Set

from app.monitoring.integrity_checker import compare_integrity, take_registry_snapshot
from app.utils.hashing import add_hashes_to_snapshot


def _path_category(path: str, registry_paths: Dict[str, Any]) -> str:
    """Map a key path to its config category."""
    if path in registry_paths.get("autorun_keys", []):
        return "autorun"

    for group_name, group_paths in registry_paths.get("security_keys", {}).items():
        if path in group_paths:
            return f"security:{group_name}"

    for group_name, group_paths in registry_paths.get("system_behavior_keys", {}).items():
        if path in group_paths:
            return f"system:{group_name}"

    return "other"


def _build_event(
    event_type: str,
    path: str,
    value_name: Optional[str],
    old_value: Any,
    new_value: Any,
    category: str,
    severity: str = "LOW",
    reason: str = "",
) -> Dict[str, Any]:
    """Build a consistent change event payload."""
    return {
        "timestamp": dt.datetime.now().isoformat(),
        "type": event_type,
        "severity": severity,
        "category": category,
        "path": path,
        "value_name": value_name,
        "old_value": old_value,
        "new_value": new_value,
        "reason": reason,
    }


def compare_snapshots(
    previous_snapshot: Dict[str, Any],
    current_snapshot: Dict[str, Any],
    registry_paths: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Detect created/deleted/modified keys and values between two snapshots."""
    events: List[Dict[str, Any]] = []
    all_paths: Set[str] = set(previous_snapshot.keys()) | set(current_snapshot.keys())

    for path in sorted(all_paths):
        prev_key = previous_snapshot.get(path, {"exists": False, "values": {}})
        curr_key = current_snapshot.get(path, {"exists": False, "values": {}})
        category = _path_category(path, registry_paths)

        if prev_key.get("exists") and not curr_key.get("exists"):
            events.append(
                _build_event(
                    "KEY_DELETED",
                    path,
                    None,
                    "exists",
                    "missing",
                    category,
                    severity="MEDIUM",
                    reason="Monitored key was deleted or became inaccessible.",
                )
            )
            continue

        if not prev_key.get("exists") and curr_key.get("exists"):
            events.append(
                _build_event(
                    "KEY_CREATED",
                    path,
                    None,
                    "missing",
                    "exists",
                    category,
                    severity="MEDIUM",
                    reason="Monitored key was created.",
                )
            )

        value_names = set(prev_key.get("values", {}).keys()) | set(curr_key.get("values", {}).keys())
        for value_name in sorted(value_names):
            prev_value = prev_key.get("values", {}).get(value_name)
            curr_value = curr_key.get("values", {}).get(value_name)

            if prev_value and not curr_value:
                events.append(
                    _build_event(
                        "VALUE_DELETED",
                        path,
                        value_name,
                        prev_value.get("data"),
                        None,
                        category,
                        severity="MEDIUM",
                        reason="Registry value removed.",
                    )
                )
                continue

            if not prev_value and curr_value:
                events.append(
                    _build_event(
                        "VALUE_CREATED",
                        path,
                        value_name,
                        None,
                        curr_value.get("data"),
                        category,
                        severity="LOW",
                        reason="Registry value added.",
                    )
                )
                continue

            if prev_value and curr_value and prev_value.get("hash") != curr_value.get("hash"):
                events.append(
                    _build_event(
                        "VALUE_MODIFIED",
                        path,
                        value_name,
                        prev_value.get("data"),
                        curr_value.get("data"),
                        category,
                        severity="MEDIUM",
                        reason="Registry value changed.",
                    )
                )

    return events


def start_monitoring(
    registry_paths: Dict[str, Any],
    baseline_snapshot: Optional[Dict[str, Any]] = None,
    interval: int = 10,
    max_cycles: Optional[int] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Poll registry periodically and yield structured change events."""
    previous_snapshot = add_hashes_to_snapshot(take_registry_snapshot(registry_paths))
    cycle = 0

    while True:
        if max_cycles is not None and cycle >= max_cycles:
            return

        time.sleep(max(interval, 1))
        current_snapshot = add_hashes_to_snapshot(take_registry_snapshot(registry_paths))
        events = compare_snapshots(previous_snapshot, current_snapshot, registry_paths)

        integrity_violations = []
        if baseline_snapshot is not None:
            integrity_violations = compare_integrity(baseline_snapshot, current_snapshot)

        yield {
            "timestamp": dt.datetime.now().isoformat(),
            "cycle": cycle,
            "events": events,
            "integrity_violations": integrity_violations,
            "snapshot": current_snapshot,
        }

        previous_snapshot = current_snapshot
        cycle += 1

