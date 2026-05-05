# Windows Registry Change Monitoring System

## Project Overview

This project is an academic + practical cybersecurity tool focused on monitoring Windows Registry changes that may indicate:

- persistence attempts (autorun abuse),
- security control tampering (Defender/Firewall/UAC),
- system behavior manipulation (shell replacement/startup changes).

It creates a baseline snapshot of important registry keys, continuously monitors them, logs suspicious modifications, and generates an investigation report.

## Features

- Baseline creation and loading (`baseline/baseline.json`)
- Modular registry polling engine
- Detection of:
  - new/deleted/modified key values
  - suspicious autorun persistence entries
  - Defender/Firewall/UAC tampering
  - shell replacement attempts
- SHA-256 integrity checks for key-value pairs
- Structured log output in text and CSV
- Colored console alerts for severity levels
- Report generation (`reports/report.txt`)
- Defensive error handling for missing keys and access issues

## Project Structure

```text
registry-monitor/
│
├── main.py
├── config/
│   └── registry_paths.py
├── monitoring/
│   ├── monitor.py
│   ├── autorun_monitor.py
│   └── integrity_checker.py
├── detection/
│   └── malware_patterns.py
├── utils/
│   ├── logger.py
│   ├── hashing.py
│   └── helpers.py
├── baseline/
│   └── baseline.json
├── logs/
│   └── registry_log.txt
├── reports/
│   └── report_generator.py
└── README.md
```

## Requirements

- Windows OS
- Python 3.9+
- Standard library modules (`winreg`, `hashlib`, `json`, etc.)
- Optional: `colorama` for colored console output

Install optional dependency:

```powershell
pip install colorama
```

## How To Run

From the `registry-monitor` directory:

```powershell
python main.py
```

Then:
1. Choose `Create new baseline` or `Load existing baseline`.
2. Set polling interval.
3. Let monitor run.
4. Stop with `Ctrl + C`.

Generated artifacts:
- Text log: `logs/registry_log.txt`
- CSV log export: `logs/registry_log.csv`
- Final report: `reports/report.txt`

## Sample Output

```text
[2026-05-05T13:40:11.243932] [VALUE_MODIFIED] [HIGH] HKLM\...\Policies\System | 1 -> 0
[ALERT] [HIGH] Autorun suspicious: Autorun path points to user-writable AppData/Temp location.
Report generated: ...\registry-monitor\reports\report.txt
CSV exported: ...\registry-monitor\logs\registry_log.csv
```

## Screenshots

- Screenshot 1: Console monitoring session (placeholder)
- Screenshot 2: `registry_log.txt` view (placeholder)
- Screenshot 3: `report.txt` summary section (placeholder)

## Notes

- Some keys may require elevated permissions for access.
- Missing or inaccessible keys are handled safely without crashing.
- This project is for security research, learning, and defensive monitoring.
