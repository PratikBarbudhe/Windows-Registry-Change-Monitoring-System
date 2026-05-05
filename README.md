# Windows Registry Change Monitoring System

Python-based cybersecurity utility for detecting suspicious changes in high-risk Windows Registry locations. The project is structured for clean development, GitHub hosting, and future packaging/deployment.

## Features

- Baseline creation and integrity comparison for monitored keys
- Change detection for key/value creation, deletion, and modification
- Suspicious pattern detection (Defender disable, Firewall disable, shell hijack, etc.)
- Autorun persistence analysis for suspicious startup entries
- Centralized logging and CSV export in `data/logs/`
- Text report generation in `app/reports/report.txt`

## Folder Structure

```text
Windows-Registry-Change-Monitoring-System/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config/
│   ├── monitoring/
│   ├── detection/
│   ├── utils/
│   └── reports/
├── data/
│   ├── baseline/
│   └── logs/
├── tests/
├── docs/
│   └── architecture.md
├── scripts/
│   └── run_monitor.bat
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── README.md
└── LICENSE
```

## Setup

### Prerequisites

- Windows 10/11
- Python 3.7+
- Administrator privileges recommended for full registry visibility

### Install

```bash
pip install -r requirements.txt
```

## How to Run

### Create/refresh baseline

```bash
python -m app.main --mode create --interval 10
```

### Start monitoring using existing baseline

```bash
python -m app.main --mode load --interval 10
```

### Optional finite run (useful for testing/CI)

```bash
python -m app.main --mode load --interval 2 --cycles 1
```

### Windows batch launcher

```bat
scripts\run_monitor.bat create
scripts\run_monitor.bat load
```

## Output Artifacts

- Baseline JSON: `data/baseline/baseline.json`
- Log text file: `data/logs/registry_log.txt`
- Log CSV file: `data/logs/registry_log.csv`
- Report file: `app/reports/report.txt`

## Sample Output

```text
[2026-05-05T13:50:12.138000] [VALUE_MODIFIED] [HIGH] HKLM\...\Winlogon | explorer.exe -> evil.exe
[ALERT] [HIGH] Autorun suspicious: Autorun command references unknown or non-standard executable.
Report generated: ...\app\reports\report.txt
CSV exported: ...\data\logs\registry_log.csv
```

## Screenshots

- `docs/screenshots/monitor-console.png` (placeholder)
- `docs/screenshots/report-output.png` (placeholder)

## Testing

```bash
pytest -q
```

## GitHub Hosting Readiness

- Single source of truth README
- Standardized Python package layout under `app/`
- Runtime artifacts isolated under `data/`
- Clean script entrypoint for local execution

## Build EXE (Windows)

Use PyInstaller:

```bash
pyinstaller --onefile app/main.py
```

Executable output is created in `dist/`.

## Future-Ready Web Dashboard

The current architecture separates detection and reporting from presentation, making it straightforward to add:

- FastAPI backend endpoints around monitor events
- WebSocket stream for live registry alerts
- Frontend dashboard for severity trends and change history

## License

MIT License. See `LICENSE`.
