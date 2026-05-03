# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Windows Registry Change Monitoring System
- Registry monitoring core with `RegistryReader` and `RegistryMonitor` classes
- Baseline comparison functionality with `BaselineComparator`
- Change detection and threat analysis with `ChangeDetector`
- Comprehensive logging and alerting with `AlertManager`
- Command-line interface with argparse support
- JSON configuration file support
- Extensive test suite with pytest and mocking
- Windows batch script helper (`run_monitor.bat`)
- Modern Python packaging with `pyproject.toml`
- Sample configuration file (`config.sample.json`)
- Complete documentation in README.md

### Features
- Monitor multiple Windows Registry hives (HKLM, HKCU, HKCR, HKU)
- Create and compare registry baselines for integrity verification
- Detect added, removed, and modified registry values
- Pattern-based malware detection (PowerShell, CMD, scripts, etc.)
- High-risk path monitoring (Run keys, Services, Winlogon)
- Multi-level logging (console and file output)
- JSON export for baselines and alerts
- Configurable monitored keys via JSON config
- Comprehensive error handling for permission issues

### Technical
- Python 3.7+ compatibility
- Type hints throughout codebase
- Extensive unit and integration tests
- Code quality tools (Black, isort, flake8, pylint, mypy)
- Coverage reporting with pytest-cov
- Proper package structure with src/ layout

## [0.1.0] - 2026-05-03

### Added
- Initial implementation of registry monitoring system
- Core classes: RegistryReader, RegistryMonitor, BaselineComparator, ChangeDetector
- Basic CLI interface
- Test framework setup
- Project documentation and README

### Dependencies
- pywin32>=305
- pyyaml>=6.0
- pytest>=7.0 (dev)
- pytest-cov>=3.0 (dev)
- flake8>=4.0 (dev)
- black>=22.0 (dev)
- pylint>=2.12 (dev)
- mypy>=0.950 (dev)

---

## Types of changes
- `Added` for new features
- `Changed` for changes in existing functionality
- `Deprecated` for soon-to-be removed features
- `Removed` for now removed features
- `Fixed` for any bug fixes
- `Security` in case of vulnerabilities

## Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Versioning
We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/yourusername/Windows-Registry-Change-Monitoring-System/tags).