# Windows Registry Change Monitoring System

A comprehensive Python-based monitoring system for detecting unauthorized, suspicious, or malicious changes in Windows Registry keys. This tool creates baselines of critical registry areas and identifies potential security threats through change detection and malware pattern recognition.

## Overview

The Windows Registry Change Monitoring System provides:
- **Registry Monitoring**: Real-time monitoring of critical Windows Registry keys
- **Baseline Management**: Create and compare registry baselines for integrity verification
- **Change Detection**: Identify added, removed, and modified registry values
- **Threat Detection**: Recognize suspicious patterns that may indicate malware activity
- **Comprehensive Logging**: Detailed logging and alerting for security incidents
- **JSON Export**: Export baselines and alerts for analysis and auditing

## Key Features

### 1. Registry Monitoring
- Monitor multiple registry hives (HKLM, HKCU, HKCR, HKU)
- Support for any registry path and value
- Robust error handling for permission issues and missing keys
- Configurable monitored keys via JSON configuration

### 2. Baseline Management
- Create snapshots of registry state at any time
- Save baselines to JSON for persistence
- Load previously saved baselines for comparison
- Timestamp tracking for audit trails

### 3. Change Detection
- **Added Values**: Detect new registry entries
- **Removed Values**: Track deletion of registry entries
- **Modified Values**: Identify changed registry values
- Summary statistics for quick overview

### 4. Threat Detection
- Pattern-based detection for malware signatures
- Suspicious pattern recognition (PowerShell, CMD, scripts, etc.)
- High-risk path monitoring (Windows Run keys, Services, etc.)
- Critical security-related value removal alerts

### 5. Logging & Alerts
- Multi-level logging (DEBUG, INFO, WARNING, CRITICAL)
- Console and file-based logging
- Structured alert generation with severity levels
- Alert summaries and statistics

## Project Structure

```
├── src/
│   ├── __init__.py
│   └── monitor.py          # Core monitoring module
├── tests/
│   ├── __init__.py
│   └── test_monitor.py     # Comprehensive test suite
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── LICENSE                # Project license
```

## Installation

### Prerequisites
- Python 3.7 or higher
- Windows OS (for registry access)
- Administrator privileges (recommended for full access)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Windows-Registry-Change-Monitoring-System.git
cd Windows-Registry-Change-Monitoring-System
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

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
