"""Main CLI application for Windows Registry Change Monitoring System."""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Tuple

from app.config.settings import load_settings
from app.detection.malware_patterns import detect_malware_patterns
from app.monitoring.autorun_monitor import detect_autorun_changes
from app.monitoring.integrity_checker import create_baseline, load_baseline
from app.monitoring.monitor import start_monitoring
from app.reports.report_generator import generate_report
from app.utils.logger import export_events_to_csv, log_event, print_alert, setup_logger


def _write_last_scan_file(timestamp: str, interval: int) -> None:
    """Persist last scan timestamp for dashboard widgets."""
    settings = load_settings(interval_seconds=interval)
    payload = {
        "last_scan_time": timestamp,
        "updated_at": timestamp,
        "interval_seconds": interval,
    }
    output = settings.data_dir / "logs" / "last_scan.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Windows Registry Change Monitoring System"
    )
    parser.add_argument(
        "--mode",
        choices=["create", "load"],
        default="load",
        help="Choose whether to create a new baseline or load existing baseline.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Polling interval in seconds.",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=None,
        help="Optional number of monitoring cycles before exiting.",
    )
    return parser.parse_args()


def _choose_baseline_mode() -> Tuple[str, int]:
    """Prompt user for baseline mode and polling interval when CLI args are absent."""
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

    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    highest = max(
        pattern_findings, key=lambda item: severity_rank.get(item["severity"], 1)
    )
    if highest.get("severity") in {"MEDIUM", "HIGH"}:
        event["severity"] = highest.get("severity")
        event["reason"] = highest.get("reason")

    return event


def run() -> None:
    """Run baseline management, monitoring loop, logging, alerting, and reporting."""
    args = parse_args()
    mode = args.mode
    interval = args.interval
    if mode not in {"create", "load"}:
        mode, interval = _choose_baseline_mode()

    settings = load_settings(interval_seconds=interval)
    logger = setup_logger(settings.log_file)
    logger.info("Application settings loaded.")

    all_events: List[Dict[str, Any]] = []
    suspicious_events: List[Dict[str, Any]] = []
    all_autorun_findings: List[Dict[str, Any]] = []
    all_integrity_violations: List[Dict[str, Any]] = []

    try:
        if mode == "create":
            baseline_data = create_baseline(
                settings.registry_paths, baseline_file=str(settings.baseline_file)
            )
            print(f"Baseline created successfully at: {settings.baseline_file}")
        else:
            baseline_data = load_baseline(baseline_file=str(settings.baseline_file))
            print(f"Baseline loaded from: {settings.baseline_file}")

        baseline_snapshot = baseline_data.get("snapshot", {})
        print(
            f"Monitoring started with interval={settings.monitoring_interval_seconds}s. "
            "Press Ctrl+C to stop."
        )

        for cycle_data in start_monitoring(
            settings.registry_paths,
            baseline_snapshot=baseline_snapshot,
            interval=settings.monitoring_interval_seconds,
            max_cycles=args.cycles,
        ):
            cycle_timestamp = cycle_data.get("timestamp")
            if cycle_timestamp:
                _write_last_scan_file(
                    cycle_timestamp, settings.monitoring_interval_seconds
                )
            events = cycle_data.get("events", [])
            integrity_violations = cycle_data.get("integrity_violations", [])

            for event in events:
                enriched = _enrich_event_with_patterns(event)
                log_event(enriched, log_file=settings.log_file, logger=logger)
                print_alert(enriched)
                all_events.append(enriched)
                if enriched.get("severity") in {"MEDIUM", "HIGH"}:
                    suspicious_events.append(enriched)

            autorun_findings = detect_autorun_changes(events)
            for finding in autorun_findings:
                if finding.get("suspicious"):
                    all_autorun_findings.append(finding)
                    print(
                        f"[ALERT] [{finding.get('severity')}] "
                        f"Autorun suspicious: {finding.get('reason')}"
                    )

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
                log_event(violation_event, log_file=settings.log_file, logger=logger)
                print_alert(violation_event)
                all_integrity_violations.append(violation)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected runtime error: %s", exc)
        print(f"Unexpected error: {exc}")
    finally:
        try:
            report_path = generate_report(
                all_events=all_events,
                suspicious_events=suspicious_events,
                autorun_findings=all_autorun_findings,
                integrity_violations=all_integrity_violations,
                output_file=str(settings.report_file),
            )
            csv_path = export_events_to_csv(all_events, output_file=settings.csv_file)
            print(f"Report generated: {report_path}")
            print(f"CSV exported: {csv_path}")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to generate final artifacts: %s", exc)
            print(f"Failed to generate final report artifacts: {exc}")


if __name__ == "__main__":
    run()
