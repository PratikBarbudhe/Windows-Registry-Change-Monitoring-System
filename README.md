# Windows Registry Change Monitoring System

A Python-based monitoring system for detecting unauthorized, suspicious, or malicious changes in Windows Registry keys. This project tracks critical registry areas, creates baselines, and reports deviations to help secure Windows endpoints.

## Overview

The Windows Registry Change Monitoring System includes:
- **Registry Monitoring**: Track critical Windows Registry keys and values
- **Baseline Comparison**: Save and compare registry snapshots over time
- **Change Detection**: Detect added, removed, and modified values
- **Threat Awareness**: Flag suspicious patterns and high-risk registry locations
- **Logging**: Support console and file-based logging
- **CI Ready**: Built with GitHub Actions for automated tests and linting

## Project Structure

```text
Windows-Registry-Change-Monitoring-System/
├── .github/
│   └── workflows/
│       └── python-app.yml   # GitHub Actions workflow for CI
├── src/
│   ├── __init__.py
│   └── monitor.py          # Core monitoring module
├── tests/
│   ├── __init__.py
│   └── test_monitor.py     # Sample unit test
├── .gitattributes
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Installation

### Prerequisites
- Python 3.7 or higher
- Windows OS for registry access
- Administrator privileges for full registry visibility

### Setup

1. Clone the repository:
```bash
git clone https://github.com/PratikBarbudhe/Windows-Registry-Change-Monitoring-System.git
cd Windows-Registry-Change-Monitoring-System
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the monitoring module:
```bash
python -m src.monitor
```

The current implementation is a starter scaffold with a placeholder entry point. Add registry scanning, baseline creation, comparison logic, and alerting in `src/monitor.py`.

## Testing

Run tests with:
```bash
pytest
```

## CI / GitHub Actions

A workflow is included at `.github/workflows/python-app.yml` to:
- install dependencies
- run tests
- run linting with `flake8`

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Usage

### Basic Usage

```python
from src.monitor import RegistryMonitor, BaselineComparator, ChangeDetector

# Initialize the monitoring system
monitor = RegistryMonitor()

# Add critical registry keys to monitor
monitor.add_monitored_key('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Run')
monitor.add_monitored_key('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Run')

# Create a baseline
monitor.create_baseline()
monitor.save_baseline('baseline.json')

# Later: Load baseline and check for changes
monitor.load_baseline('baseline.json')
comparator = BaselineComparator(monitor)

# Detect changes
changes = comparator.compare_current_state()
print(f"Changes detected: {comparator.get_summary()}")

# Check for suspicious changes
detector = ChangeDetector(comparator)
alerts = detector.detect_changes()
detector.save_alerts('alerts.json')
```

### Command-Line Usage

Run the monitor directly from the command line:

```bash
python src/monitor.py --create-baseline --baseline registry_baseline.json
python src/monitor.py --compare --baseline registry_baseline.json --alerts registry_alerts.json
```

Available options:
- `--config <path>`: JSON config file with monitored registry keys
- `--baseline <path>`: Baseline JSON file path
- `--alerts <path>`: Alerts JSON file path
- `--create-baseline`: Create or refresh the registry baseline
- `--compare`: Compare current registry state to the baseline

### Configuration File

Create a `config.json` file to configure monitored keys:

```json
{
  "monitored_keys": [
    {
      "hive": "HKLM",
      "path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    },
    {
      "hive": "HKCU",
      "path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    },
    {
      "hive": "HKLM",
      "path": "System\\CurrentControlSet\\Services"
    }
  ]
}
```

Load configuration:
```python
monitor = RegistryMonitor('config.json')
```

## Classes

### RegistryReader
Handles reading Windows Registry keys and values.

```python
reader = RegistryReader()
values = reader.get_registry_values('HKLM', 'Software\\Test')
```

### RegistryMonitor
Main monitoring class for managing registry keys and baselines.

```python
monitor = RegistryMonitor()
monitor.add_monitored_key('HKLM', 'Software\\MyKey')
monitor.create_baseline()
monitor.save_baseline('my_baseline.json')
```

### BaselineComparator
Compares current registry state with baseline.

```python
comparator = BaselineComparator(monitor)
changes = comparator.compare_current_state()
summary = comparator.get_summary()
```

### ChangeDetector
Detects suspicious or malicious registry changes.

```python
detector = ChangeDetector(comparator)
alerts = detector.detect_changes()
detector.save_alerts('alerts.json')
```

### AlertManager
Handles logging and alert management.

```python
alert_manager = AlertManager('monitor.log')
alert_manager.log_baseline_created(5)
alert_manager.log_comparison_complete(summary, len(alerts))
```

## Testing

Run the comprehensive test suite:

```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ --cov=src --cov-report=html
```

Test coverage includes:
- Registry Reader functionality
- Monitor baseline creation and loading
- Change comparison and detection
- Suspicious pattern recognition
- File I/O operations
- Integration tests

## Monitored Registry Areas

By default, the system monitors:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` - Autostart programs
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` - User autostart programs
- `System\CurrentControlSet\Services` - Windows services
- `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` - Logon settings

## Suspicious Patterns

The system detects suspicious patterns including:
- PowerShell execution (`powershell`)
- Command line execution (`cmd`)
- VBScript execution (`vbscript`)
- WScript execution (`wscript`)
- Certificate utility abuse (`certutil`)
- Registry service abuse (`regsvcs`, `regasm`)
- HTML application execution (`mshta`)

## Alert Severity Levels

- **CRITICAL**: Security-related value removal or high-risk modifications
- **SUSPICIOUS**: New entries with malware patterns or high-risk path modifications
- **INFO**: General informational alerts

## Output Files

The system generates the following output files:

- `registry_baseline.json` - Registry baseline snapshot
- `registry_alerts.json` - Detected security alerts
- `registry_monitor.log` - System log file

## Logging

The system provides comprehensive logging:

- **Console Output**: INFO level and above
- **File Output**: DEBUG level and above
- **Timestamps**: All events are timestamped
- **Contextual Info**: Registry keys, values, and descriptions included

## Limitations and Notes

- Requires Windows OS and Python 3.7+
- Administrator privileges recommended for full registry access
- Some registry keys may require elevated permissions
- Cannot monitor registry changes in real-time (requires periodic baseline comparisons)

## Performance Considerations

- First baseline creation may take time depending on registry size
- Baseline comparison is efficient even with many monitored keys
- JSON serialization suitable for baseline and alert storage

## Security Recommendations

- Run with administrator privileges for comprehensive monitoring
- Store baselines and alerts in secure locations
- Review alerts regularly for security incidents
- Use configuration file to customize monitored keys
- Integrate with SIEM systems for centralized monitoring

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for authorized security monitoring and incident response purposes. Ensure you have proper authorization before monitoring registry changes on systems you do not own or manage.

## Support

For issues, questions, or suggestions, please open an issue on the GitHub repository.
