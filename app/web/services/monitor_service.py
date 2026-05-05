"""Threaded monitoring service for Flask dashboard controls."""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from app.config.settings import load_settings
from app.detection.malware_patterns import detect_malware_patterns
from app.monitoring.autorun_monitor import detect_autorun_changes
from app.monitoring.integrity_checker import create_baseline, load_baseline
from app.monitoring.monitor import start_monitoring
from app.reports.report_generator import generate_report
from app.utils.logger import export_events_to_csv, log_event, print_alert, setup_logger


class MonitorService:
    """Manage background monitoring thread and runtime control state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._interval_seconds = 10
        self._running = False
        self._last_scan_time = "N/A"
        self._last_error = ""
        self._settings = load_settings(interval_seconds=self._interval_seconds)
        self._last_scan_file = self._settings.data_dir / "logs" / "last_scan.json"
        self._logger = setup_logger(self._settings.log_file)

    def _write_last_scan(self, timestamp: str) -> None:
        """Persist last scan timestamp for dashboard consumption."""
        self._last_scan_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_scan_time": timestamp,
            "updated_at": datetime.now().isoformat(),
            "interval_seconds": self._interval_seconds,
            "running": self._running,
        }
        self._last_scan_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        with self._lock:
            self._last_scan_time = timestamp

    def _enrich_event_with_patterns(self, event: Dict[str, Any]) -> Dict[str, Any]:
        findings = detect_malware_patterns(event)
        if not findings:
            return event
        rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        highest = max(findings, key=lambda item: rank.get(item.get("severity", "LOW"), 1))
        if highest.get("severity") in {"MEDIUM", "HIGH"}:
            event["severity"] = highest.get("severity")
            event["reason"] = highest.get("reason")
        return event

    def _ensure_baseline(self) -> Dict[str, Any]:
        baseline_data = load_baseline(str(self._settings.baseline_file))
        if baseline_data.get("snapshot"):
            return baseline_data
        return create_baseline(
            self._settings.registry_paths,
            baseline_file=str(self._settings.baseline_file),
        )

    def _worker(self) -> None:
        """Background monitor loop."""
        all_events: List[Dict[str, Any]] = []
        suspicious_events: List[Dict[str, Any]] = []
        all_autorun_findings: List[Dict[str, Any]] = []
        all_integrity_violations: List[Dict[str, Any]] = []

        try:
            baseline_data = self._ensure_baseline()
            baseline_snapshot = baseline_data.get("snapshot", {})
            monitor_stream = start_monitoring(
                self._settings.registry_paths,
                baseline_snapshot=baseline_snapshot,
                interval=self._interval_seconds,
            )
            for cycle_data in monitor_stream:
                if self._stop_event.is_set():
                    break

                cycle_timestamp = cycle_data.get("timestamp", datetime.now().isoformat())
                self._write_last_scan(cycle_timestamp)

                events = cycle_data.get("events", [])
                integrity_violations = cycle_data.get("integrity_violations", [])

                for event in events:
                    enriched = self._enrich_event_with_patterns(event)
                    log_event(enriched, log_file=self._settings.log_file, logger=self._logger)
                    print_alert(enriched)
                    all_events.append(enriched)
                    if enriched.get("severity") in {"MEDIUM", "HIGH"}:
                        suspicious_events.append(enriched)

                autorun_findings = detect_autorun_changes(events)
                for finding in autorun_findings:
                    if finding.get("suspicious"):
                        all_autorun_findings.append(finding)

                for violation in integrity_violations:
                    violation_event = {
                        "timestamp": cycle_timestamp,
                        "type": violation.get("type"),
                        "severity": violation.get("severity"),
                        "category": "integrity",
                        "path": violation.get("path"),
                        "value_name": violation.get("value_name"),
                        "old_value": violation.get("old_value"),
                        "new_value": violation.get("new_value"),
                        "reason": violation.get("reason"),
                    }
                    log_event(violation_event, log_file=self._settings.log_file, logger=self._logger)
                    print_alert(violation_event)
                    all_integrity_violations.append(violation)

                export_events_to_csv(all_events, output_file=self._settings.csv_file)
                generate_report(
                    all_events=all_events,
                    suspicious_events=suspicious_events,
                    autorun_findings=all_autorun_findings,
                    integrity_violations=all_integrity_violations,
                    output_file=str(self._settings.report_file),
                )
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._last_error = str(exc)
            self._logger.exception("Monitoring service error: %s", exc)
        finally:
            with self._lock:
                self._running = False
            # Ensure persisted state marks stopped.
            if self._last_scan_time == "N/A":
                self._write_last_scan(datetime.now().isoformat())
            else:
                self._write_last_scan(self._last_scan_time)

    def start(self) -> bool:
        """Start monitor thread if not running."""
        with self._lock:
            if self._running:
                return False
            self._stop_event.clear()
            self._settings = load_settings(interval_seconds=self._interval_seconds)
            self._thread = threading.Thread(target=self._worker, daemon=True, name="RegistryMonitorThread")
            self._running = True
            self._thread.start()
        return True

    def stop(self) -> bool:
        """Request monitor shutdown."""
        with self._lock:
            if not self._running:
                return False
            self._stop_event.set()
        return True

    def set_interval(self, seconds: int) -> None:
        """Update interval; affects next start."""
        with self._lock:
            self._interval_seconds = max(1, int(seconds))

    def generate_report_now(self) -> str:
        """Generate report from current CSV rows."""
        # Reuse existing pipeline artifact generation from log-backed data.
        rows: List[Dict[str, Any]] = []
        if self._settings.csv_file.exists():
            import csv

            with open(self._settings.csv_file, "r", encoding="utf-8", newline="") as handle:
                for row in csv.DictReader(handle):
                    rows.append(row)

        report_path = generate_report(
            all_events=rows,
            suspicious_events=[row for row in rows if row.get("severity") in {"MEDIUM", "HIGH"}],
            autorun_findings=[row for row in rows if "run" in str(row.get("path", "")).lower()],
            integrity_violations=[row for row in rows if row.get("category") == "integrity"],
            output_file=str(self._settings.report_file),
        )
        return report_path

    def get_status(self) -> Dict[str, Any]:
        """Expose current service state for route handlers/UI."""
        with self._lock:
            return {
                "running": self._running,
                "interval_seconds": self._interval_seconds,
                "last_scan_time": self._last_scan_time,
                "last_error": self._last_error,
            }

