"""Focused tests for refactored app package behavior."""

from __future__ import annotations

from app.config.settings import load_settings
from app.detection.malware_patterns import detect_malware_patterns
from app.monitoring.autorun_monitor import detect_autorun_changes
from app.monitoring.monitor import compare_snapshots


def test_settings_paths_are_initialized() -> None:
    settings = load_settings(interval_seconds=2)
    assert settings.monitoring_interval_seconds == 2
    assert settings.data_dir.exists()
    assert settings.baseline_file.parent.exists()
    assert settings.log_file.parent.exists()


def test_compare_snapshots_detects_value_modification() -> None:
    path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    registry_paths = {"autorun_keys": [path], "security_keys": {}, "system_behavior_keys": {}}
    previous = {
        path: {
            "exists": True,
            "values": {"Updater": {"data": "a.exe", "type": 1, "hash": "old"}},
        }
    }
    current = {
        path: {
            "exists": True,
            "values": {"Updater": {"data": "b.exe", "type": 1, "hash": "new"}},
        }
    }
    events = compare_snapshots(previous, current, registry_paths)
    assert any(event["type"] == "VALUE_MODIFIED" for event in events)


def test_malware_pattern_detection_high_severity() -> None:
    event = {
        "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "value_name": "EnableLUA",
        "new_value": 0,
    }
    findings = detect_malware_patterns(event)
    assert any(item["severity"] == "HIGH" for item in findings)


def test_autorun_change_detection_flags_suspicious_path() -> None:
    events = [
        {
            "type": "VALUE_CREATED",
            "category": "autorun",
            "path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "BadEntry",
            "new_value": r"C:\Users\User\AppData\Temp\evil.exe",
        }
    ]
    findings = detect_autorun_changes(events)
    assert findings
    assert findings[0]["suspicious"] is True
