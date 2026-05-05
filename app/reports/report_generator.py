"""Report generation for registry monitoring results."""

from __future__ import annotations

import datetime as dt
import os
from typing import Any, Dict, List


def generate_report(
    all_events: List[Dict[str, Any]],
    suspicious_events: List[Dict[str, Any]],
    autorun_findings: List[Dict[str, Any]],
    integrity_violations: List[Dict[str, Any]],
    output_file: str = "app/reports/report.txt",
) -> str:
    """Generate a plain-text report containing monitoring outcomes."""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for event in all_events:
        severity = str(event.get("severity", "LOW")).upper()
        if severity not in severity_counts:
            severity = "LOW"
        severity_counts[severity] += 1

    lines = [
        "Windows Registry Change Monitoring Report",
        "=" * 45,
        f"Generated: {dt.datetime.now().isoformat()}",
        "",
        "Summary",
        "-" * 20,
        f"Total changes: {len(all_events)}",
        f"Suspicious activities: {len(suspicious_events)}",
        f"Autorun detections: {len(autorun_findings)}",
        f"Integrity violations: {len(integrity_violations)}",
        (
            f"Severity breakdown: LOW={severity_counts['LOW']}, "
            f"MEDIUM={severity_counts['MEDIUM']}, HIGH={severity_counts['HIGH']}"
        ),
        "",
        "Suspicious Activities",
        "-" * 20,
    ]

    if suspicious_events:
        for event in suspicious_events:
            lines.append(
                f"[{event.get('severity')}] {event.get('path')}::{event.get('value_name')} "
                f"- {event.get('reason')}"
            )
    else:
        lines.append("No suspicious activity detected.")

    lines.extend(["", "Autorun Detections", "-" * 20])
    if autorun_findings:
        for finding in autorun_findings:
            lines.append(
                f"[{finding.get('severity')}] {finding.get('path')}::{finding.get('value_name')} "
                f"- {finding.get('reason')}"
            )
    else:
        lines.append("No suspicious autorun changes detected.")

    lines.extend(["", "Integrity Violations", "-" * 20])
    if integrity_violations:
        for violation in integrity_violations:
            lines.append(
                f"[{violation.get('severity')}] {violation.get('type')} at {violation.get('path')} "
                f"- {violation.get('reason')}"
            )
    else:
        lines.append("No integrity violations detected.")

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    return output_file

