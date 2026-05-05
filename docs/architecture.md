# Architecture

## Overview

The monitoring system is organized around a modular `app` package and a clean separation between code and runtime state.

- `app/main.py`: orchestrates config loading, baseline handling, monitor loop, logging, and report generation.
- `app/config`: settings and monitored registry paths.
- `app/monitoring`: snapshot collection, integrity checks, and change detection loop.
- `app/detection`: suspicious-pattern analysis for high-risk changes.
- `app/utils`: registry helpers, hashing, and centralized logging utilities.
- `app/reports`: text report generation.

## Runtime Data Flow

1. `app.main` loads `Settings` from `app.config.settings`.
2. Baseline is created/loaded from `data/baseline/baseline.json`.
3. `start_monitoring` polls registry state and emits normalized events.
4. Events are enriched by detection logic and written to `data/logs/registry_log.txt`.
5. CSV export is written to `data/logs/registry_log.csv`.
6. Summary report is generated at `app/reports/report.txt`.

## Entry Point

Use:

```bash
python -m app.main --mode load --interval 10
```

Optional finite run (good for CI smoke tests):

```bash
python -m app.main --mode load --interval 2 --cycles 1
```

