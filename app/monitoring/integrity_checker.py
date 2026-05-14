"""Baseline creation and integrity validation utilities."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, cast

from app.utils.hashing import add_hashes_to_snapshot
from app.utils.helpers import flatten_registry_paths, list_registry_values


def take_registry_snapshot(registry_paths: Dict[str, Any]) -> Dict[str, Any]:
    """Read all configured registry keys and build a point-in-time snapshot."""
    snapshot: Dict[str, Any] = {}
    for path in flatten_registry_paths(registry_paths):
        snapshot[path] = list_registry_values(path)
    return snapshot


def create_baseline(
    registry_paths: Dict[str, Any],
    baseline_file: str = "data/baseline/baseline.json",
) -> Dict[str, Any]:
    """Create and save a baseline snapshot with hashes for future comparisons."""
    raw_snapshot = take_registry_snapshot(registry_paths)
    baseline_data = {
        "meta": {"baseline_version": 1},
        "snapshot": add_hashes_to_snapshot(raw_snapshot),
    }

    os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
    with open(baseline_file, "w", encoding="utf-8") as file:
        json.dump(baseline_data, file, indent=2)

    return baseline_data


def load_baseline(baseline_file: str = "data/baseline/baseline.json") -> Dict[str, Any]:
    """Load baseline JSON from disk and return empty baseline if missing/corrupt."""
    if not os.path.exists(baseline_file):
        return {"meta": {"baseline_version": 1}, "snapshot": {}}

    try:
        with open(baseline_file, "r", encoding="utf-8") as file:
            return cast(Dict[str, Any], json.load(file))
    except (json.JSONDecodeError, OSError):
        return {"meta": {"baseline_version": 1}, "snapshot": {}}


def compare_integrity(
    baseline_snapshot: Dict[str, Any],
    current_snapshot: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Compare baseline and current snapshots to find integrity violations."""
    violations: List[Dict[str, Any]] = []

    all_paths = sorted(set(baseline_snapshot.keys()) | set(current_snapshot.keys()))
    for path in all_paths:
        base_key = baseline_snapshot.get(path, {"exists": False, "values": {}})
        curr_key = current_snapshot.get(path, {"exists": False, "values": {}})

        if base_key.get("exists") and not curr_key.get("exists"):
            violations.append(
                {
                    "type": "KEY_DELETED",
                    "severity": "MEDIUM",
                    "path": path,
                    "reason": "Monitored key missing compared to baseline.",
                }
            )
            continue

        if not base_key.get("exists") and curr_key.get("exists"):
            violations.append(
                {
                    "type": "KEY_CREATED",
                    "severity": "LOW",
                    "path": path,
                    "reason": "Monitored key now exists but was absent in baseline.",
                }
            )

        all_values = sorted(
            set(base_key.get("values", {}).keys())
            | set(curr_key.get("values", {}).keys())
        )
        for value_name in all_values:
            base_value = base_key.get("values", {}).get(value_name)
            curr_value = curr_key.get("values", {}).get(value_name)

            if base_value and not curr_value:
                violations.append(
                    {
                        "type": "VALUE_DELETED",
                        "severity": "MEDIUM",
                        "path": path,
                        "value_name": value_name,
                        "reason": "Value removed from monitored key.",
                    }
                )
                continue

            if not base_value and curr_value:
                violations.append(
                    {
                        "type": "VALUE_CREATED",
                        "severity": "LOW",
                        "path": path,
                        "value_name": value_name,
                        "reason": "New value created in monitored key.",
                    }
                )
                continue

            if (
                base_value
                and curr_value
                and base_value.get("hash") != curr_value.get("hash")
            ):
                violations.append(
                    {
                        "type": "VALUE_MODIFIED",
                        "severity": "MEDIUM",
                        "path": path,
                        "value_name": value_name,
                        "reason": "Hash mismatch against baseline.",
                        "old_value": base_value.get("data"),
                        "new_value": curr_value.get("data"),
                    }
                )

    return violations
