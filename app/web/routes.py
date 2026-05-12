"""Web routes and data loading utilities for dashboard UI."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, cast

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from app.web.services.monitor_service import MonitorService

BASE_DIR = Path(__file__).resolve().parents[2]
LOG_TXT_PATH = BASE_DIR / "data" / "logs" / "registry_log.txt"
LOG_CSV_PATH = BASE_DIR / "data" / "logs" / "registry_log.csv"
REPORT_PATH = BASE_DIR / "app" / "reports" / "report.txt"
BASELINE_PATH = BASE_DIR / "data" / "baseline" / "baseline.json"
LAST_SCAN_PATH = BASE_DIR / "data" / "logs" / "last_scan.json"
INTERVAL_OPTIONS = [5, 10, 30, 60, 300, 600]
MONITOR_SERVICE = MonitorService()

LOG_PATTERN = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+"
    r"\[(?P<type>[^\]]+)\]\s+"
    r"\[(?P<severity>[^\]]+)\]\s+"
    r"(?P<path>.+?)\s+\|\s+"
    r"(?P<old>.*?)\s+->\s+(?P<new>.*)$"
)


def _safe_read_text(path: Path) -> str:
    """Read text content safely."""
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_log_text() -> List[Dict[str, str]]:
    """Parse text logs into structured records."""
    content = _safe_read_text(LOG_TXT_PATH)
    rows: List[Dict[str, str]] = []
    for line in content.splitlines():
        match = LOG_PATTERN.match(line.strip())
        if not match:
            continue
        rows.append(
            {
                "timestamp": match.group("timestamp"),
                "type": match.group("type"),
                "severity": match.group("severity").upper(),
                "path": match.group("path"),
                "old_value": match.group("old"),
                "new_value": match.group("new"),
                "reason": "",
                "value_name": "",
                "category": "",
            }
        )
    return rows


def _load_log_rows() -> List[Dict[str, str]]:
    """Load log rows from CSV with fallback to parsed text logs."""
    if LOG_CSV_PATH.exists():
        rows: List[Dict[str, str]] = []
        with open(LOG_CSV_PATH, "r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                rows.append(
                    {
                        "timestamp": row.get("timestamp", ""),
                        "type": row.get("type", ""),
                        "severity": row.get("severity", "LOW").upper(),
                        "category": row.get("category", ""),
                        "path": row.get("path", ""),
                        "value_name": row.get("value_name", ""),
                        "old_value": row.get("old_value", ""),
                        "new_value": row.get("new_value", ""),
                        "reason": row.get("reason", ""),
                    }
                )
        if rows:
            return rows

    return _parse_log_text()


def _last_scan_time(rows: List[Dict[str, str]]) -> str:
    """Return latest event timestamp."""
    if LAST_SCAN_PATH.exists():
        try:
            payload = cast(
                Dict[str, Any], json.loads(LAST_SCAN_PATH.read_text(encoding="utf-8"))
            )
            return str(payload.get("last_scan_time", "N/A"))
        except json.JSONDecodeError:
            pass
    if rows:
        return rows[-1].get("timestamp", "N/A")
    return "N/A"


def _count_autorun_entries(rows: List[Dict[str, str]]) -> int:
    """Count autorun-related entries."""
    count = 0
    for row in rows:
        path = row.get("path", "").lower()
        category = row.get("category", "").lower()
        if "run" in path or "autorun" in category:
            count += 1
    return count


def _load_baseline_meta() -> Dict[str, Any]:
    """Load baseline metadata."""
    if not BASELINE_PATH.exists():
        return {"exists": False, "version": "N/A", "keys": 0}
    try:
        content = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        snapshot = content.get("snapshot", {})
        meta = content.get("meta", {})
        key_names = list(snapshot.keys())
        return {
            "exists": True,
            "version": meta.get("baseline_version", "N/A"),
            "keys": len(snapshot),
            "key_list": key_names[:8],
        }
    except json.JSONDecodeError:
        return {"exists": False, "version": "Invalid JSON", "keys": 0, "key_list": []}


def _load_report_summary() -> Dict[str, Any]:
    """Read report file and extract top summary lines."""
    text = _safe_read_text(REPORT_PATH)
    if not text:
        return {"exists": False, "text": "Report not generated yet."}
    lines = [line for line in text.splitlines() if line.strip()]
    top = "\n".join(lines[:12])
    return {"exists": True, "text": top}


def register_routes(app: Flask) -> None:
    """Register web routes."""

    @app.route("/")
    def index() -> str:
        toast = request.args.get("toast", "")
        rows = _load_log_rows()
        high_risk_count = sum(1 for row in rows if row.get("severity") == "HIGH")
        medium_count = sum(1 for row in rows if row.get("severity") == "MEDIUM")
        service_status = MONITOR_SERVICE.get_status()
        dashboard_data = {
            "total_changes": len(rows),
            "suspicious_activities": high_risk_count + medium_count,
            "autorun_entries": _count_autorun_entries(rows),
            "last_scan_time": _last_scan_time(rows),
            "baseline": _load_baseline_meta(),
            "report": _load_report_summary(),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "monitor": service_status,
            "toast": toast,
        }
        return render_template(
            "index.html",
            data=dashboard_data,
            refresh_seconds=8,
            interval_options=INTERVAL_OPTIONS,
        )

    @app.route("/logs")
    def logs() -> str:
        q = request.args.get("q", "").strip().lower()
        severity_filter = request.args.get("severity", "").strip().upper()
        rows = _load_log_rows()

        if severity_filter in {"LOW", "MEDIUM", "HIGH"}:
            rows = [
                row
                for row in rows
                if row.get("severity", "").upper() == severity_filter
            ]

        if q:
            filtered: List[Dict[str, str]] = []
            for row in rows:
                haystack = " ".join(str(value) for value in row.values()).lower()
                if q in haystack:
                    filtered.append(row)
            rows = filtered

        return render_template(
            "logs.html",
            rows=rows,
            query=q,
            severity=severity_filter,
            refresh_seconds=10,
        )

    @app.route("/alerts")
    def alerts() -> str:
        rows = _load_log_rows()
        high_alerts = [row for row in rows if row.get("severity") == "HIGH"]
        medium_alerts = [row for row in rows if row.get("severity") == "MEDIUM"]
        return render_template(
            "alerts.html",
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            refresh_seconds=10,
        )

    @app.route("/download/report")
    def download_report() -> Any:
        if REPORT_PATH.exists():
            return send_file(
                REPORT_PATH, as_attachment=True, download_name="registry_report.txt"
            )
        return Response(
            "Report not found. Run monitor first.", status=404, mimetype="text/plain"
        )

    @app.route("/monitor/start", methods=["POST"])
    def start_monitoring_route() -> Any:
        started = MONITOR_SERVICE.start()
        toast = "Monitoring Started" if started else "Monitoring already running"
        return redirect(url_for("index", toast=toast))

    @app.route("/monitor/stop", methods=["POST"])
    def stop_monitoring_route() -> Any:
        stopped = MONITOR_SERVICE.stop()
        toast = "Monitoring Stopped" if stopped else "Monitoring already stopped"
        return redirect(url_for("index", toast=toast))

    @app.route("/monitor/interval", methods=["POST"])
    def set_interval_route() -> Any:
        selected = request.form.get("interval_seconds", "10")
        try:
            seconds = int(selected)
        except ValueError:
            seconds = 10
        MONITOR_SERVICE.set_interval(seconds)
        return redirect(
            url_for("index", toast=f"Scan interval updated to {seconds} seconds")
        )

    @app.route("/monitor/generate-report", methods=["POST"])
    def generate_report_route() -> Any:
        MONITOR_SERVICE.generate_report_now()
        return redirect(url_for("index", toast="Report generated"))

    @app.route("/api/status")
    def api_status() -> Any:
        payload = MONITOR_SERVICE.get_status()
        payload["last_scan_time"] = _last_scan_time(_load_log_rows())
        return jsonify(payload)
