"""Centralized runtime settings for monitor execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.config.registry_paths import REGISTRY_PATHS


@dataclass(frozen=True)
class Settings:
    """Resolved runtime settings with filesystem paths and polling options."""

    project_root: Path
    data_dir: Path
    baseline_file: Path
    log_file: Path
    csv_file: Path
    report_file: Path
    monitoring_interval_seconds: int
    registry_paths: dict


def load_settings(interval_seconds: int = 10) -> Settings:
    """Load application settings and ensure runtime directories exist."""
    project_root = Path(__file__).resolve().parents[2]
    data_dir = project_root / "data"
    baseline_dir = data_dir / "baseline"
    logs_dir = data_dir / "logs"
    reports_dir = project_root / "app" / "reports"

    baseline_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        project_root=project_root,
        data_dir=data_dir,
        baseline_file=baseline_dir / "baseline.json",
        log_file=logs_dir / "registry_log.txt",
        csv_file=logs_dir / "registry_log.csv",
        report_file=reports_dir / "report.txt",
        monitoring_interval_seconds=max(interval_seconds, 1),
        registry_paths=REGISTRY_PATHS,
    )

