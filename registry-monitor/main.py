"""Main CLI application for Windows Registry Change Monitoring System."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from config.registry_paths import REGISTRY_PATHS
from detection.malware_patterns import detect_malware_patterns
from monitoring.autorun_monitor import detect_autorun_changes
from monitoring.integrity_checker import create_baseline, load_baseline
from monitoring.monitor import start_monitoring
from reports.report_generator import generate_report
from utils.logger import export_events_to_csv, log_event, print_alert

APP_DIR = Path(__file__).resolve().parent
BASELINE_FILE = str(APP_DIR / "baseline" / "baseline.json")
LOG_FILE = str(APP_DIR / "logs" / "registry_log.txt")
CSV_FILE = str(APP_DIR / "logs" / "registry_log.csv")
REPORT_FILE = str(APP_DIR / "reports" / "report.txt")


def _choose_baseline_mode() -> Tuple[str, int]:
    """Prompt user for baseline mode and polling interval."""
    print("Windows Registry Change Monitoring System")
    print("=" * 45)
    print("1) Create new baseline")
    print("2) Load existing baseline")

    selection = input("Choose an option (1/2): ").strip()
    mode = "create" if selection == "1" else "load"

    interval_text = input("Polling interval in seconds (default 10): ").strip()
    try:
        interval = int(interval_text) if interval_text else 10
    except ValueError:
        interval = 10

    return mode, max(interval, 1)


def _enrich_event_with_patterns(event: Dict[str, Any]) -> Dict[str, Any]:
    """Apply malware pattern checks and update event severity/reason."""
    pattern_findings = detect_malware_patterns(event)
    if not pattern_findings:
        return event

    highest = max(pattern_findings, key=lambda item: {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(item["severity"], 1))
    if highest.get("severity") in {"MEDIUM", "HIGH"}:
        event["severity"] = highest.get("severity")
        event["reason"] = highest.get("reason")

    return event


def run() -> None:
    """Run baseline management, monitoring loop, logging, alerting, and reporting."""
    all_events: List[Dict[str, Any]] = []
    suspicious_events: List[Dict[str, Any]] = []
    all_autorun_findings: List[Dict[str, Any]] = []
    all_integrity_violations: List[Dict[str, Any]] = []

    try:
        mode, interval = _choose_baseline_mode()
        if mode == "create":
            baseline_data = create_baseline(REGISTRY_PATHS, baseline_file=BASELINE_FILE)
            print("Baseline created successfully.")
        else:
            baseline_data = load_baseline(baseline_file=BASELINE_FILE)
            print("Baseline loaded.")

        baseline_snapshot = baseline_data.get("snapshot", {})
        print(f"Monitoring started with interval={interval}s. Press Ctrl+C to stop.")

        for cycle_data in start_monitoring(REGISTRY_PATHS, baseline_snapshot=baseline_snapshot, interval=interval):
            events = cycle_data.get("events", [])
            integrity_violations = cycle_data.get("integrity_violations", [])

            for event in events:
                enriched = _enrich_event_with_patterns(event)
                log_event(enriched, log_file=LOG_FILE)
                print_alert(enriched)
                all_events.append(enriched)
                if enriched.get("severity") in {"MEDIUM", "HIGH"}:
                    suspicious_events.append(enriched)

            autorun_findings = detect_autorun_changes(events)
            for finding in autorun_findings:
                if finding.get("suspicious"):
                    all_autorun_findings.append(finding)
                    print(f"[ALERT] [{finding.get('severity')}] Autorun suspicious: {finding.get('reason')}")

            for violation in integrity_violations:
                violation_event = {
                    "timestamp": cycle_data.get("timestamp"),
                    "type": violation.get("type"),
                    "severity": violation.get("severity"),
                    "category": "integrity",
                    "path": violation.get("path"),
                    "value_name": violation.get("value_name"),
                    "old_value": violation.get("old_value"),
                    "new_value": violation.get("new_value"),
                    "reason": violation.get("reason"),
                }
                log_event(violation_event, log_file=LOG_FILE)
                print_alert(violation_event)
                all_integrity_violations.append(violation)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as exc:  # noqa: BLE001
        print(f"Unexpected error: {exc}")
    finally:
        try:
            report_path = generate_report(
                all_events=all_events,
                suspicious_events=suspicious_events,
                autorun_findings=all_autorun_findings,
                integrity_violations=all_integrity_violations,
                output_file=REPORT_FILE,
            )
            csv_path = export_events_to_csv(all_events, output_file=CSV_FILE)
            print(f"Report generated: {report_path}")
            print(f"CSV exported: {csv_path}")
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to generate final report artifacts: {exc}")


if __name__ == "__main__":
    run()

