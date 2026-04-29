"""
Windows Registry Change Monitoring System
Main monitoring module
"""
import winreg
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path
import json
from datetime import datetime


class RegistryReader:
    """Handles reading and accessing Windows Registry keys"""
    
    def __init__(self):
        self.hive_map = {
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKCR': winreg.HKEY_CLASSES_ROOT,
            'HKU': winreg.HKEY_USERS,
        }
    
    def get_registry_values(self, hive: str, path: str) -> Dict[str, Any]:
        """Read all values from a registry key"""
        try:
            hkey = self.hive_map.get(hive)
            if not hkey:
                raise ValueError(f"Unknown hive: {hive}")
            
            registry_key = winreg.OpenKey(hkey, path)
            values = {}
            
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(registry_key, i)
                    values[name] = {'data': data, 'type': reg_type}
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(registry_key)
            return values
        except PermissionError:
            logging.warning(f"Permission denied accessing {hive}\\{path}")
            return {}
        except FileNotFoundError:
            logging.warning(f"Registry key not found: {hive}\\{path}")
            return {}


class RegistryMonitor:
    """Core registry monitoring system"""
    
    def __init__(self, config_file: str = None):
        self.reader = RegistryReader()
        self.monitored_keys: List[Tuple[str, str]] = []
        self.baseline: Dict[str, Any] = {}
        self.logger = self._setup_logger()
        
        if config_file:
            self.load_config(config_file)
    
    def _setup_logger(self) -> logging.Logger:
        """Configure logging for the monitor"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.FileHandler('registry_monitor.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def load_config(self, config_file: str):
        """Load monitoring configuration from file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            for key_config in config.get('monitored_keys', []):
                hive = key_config.get('hive')
                path = key_config.get('path')
                if hive and path:
                    self.monitored_keys.append((hive, path))
            
            self.logger.info(f"Loaded {len(self.monitored_keys)} monitored keys from config")
        except FileNotFoundError:
            self.logger.error(f"Config file not found: {config_file}")
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON in config file: {config_file}")
    
    def add_monitored_key(self, hive: str, path: str):
        """Add a registry key to monitor"""
        if (hive, path) not in self.monitored_keys:
            self.monitored_keys.append((hive, path))
            self.logger.info(f"Added monitored key: {hive}\\{path}")
    
    def create_baseline(self) -> Dict[str, Any]:
        """Create a baseline snapshot of all monitored keys"""
        self.baseline = {}
        timestamp = datetime.now().isoformat()
        
        for hive, path in self.monitored_keys:
            key_id = f"{hive}\\{path}"
            values = self.reader.get_registry_values(hive, path)
            self.baseline[key_id] = {
                'values': values,
                'timestamp': timestamp
            }
            self.logger.info(f"Baseline created for {key_id}")
        
        return self.baseline
    
    def save_baseline(self, filename: str = 'registry_baseline.json'):
        """Save baseline to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.baseline, f, indent=2, default=str)
            self.logger.info(f"Baseline saved to {filename}")
        except IOError as e:
            self.logger.error(f"Failed to save baseline: {e}")
    
    def load_baseline(self, filename: str = 'registry_baseline.json'):
        """Load baseline from file"""
        try:
            with open(filename, 'r') as f:
                self.baseline = json.load(f)
            self.logger.info(f"Baseline loaded from {filename}")
        except FileNotFoundError:
            self.logger.warning(f"Baseline file not found: {filename}")
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON in baseline file: {filename}")


class BaselineComparator:
    """Compare current registry state against baseline"""
    
    def __init__(self, monitor: RegistryMonitor):
        self.monitor = monitor
        self.logger = logging.getLogger(__name__)
    
    def compare_current_state(self) -> Dict[str, Any]:
        """Compare current registry state with baseline"""
        if not self.monitor.baseline:
            self.logger.warning("No baseline available for comparison")
            return {}
        
        changes = {
            'added': {},
            'removed': {},
            'modified': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Compare each monitored key
        for key_id, baseline_data in self.monitor.baseline.items():
            hive, path = key_id.split('\\', 1)
            current_values = self.monitor.reader.get_registry_values(hive, path)
            baseline_values = baseline_data.get('values', {})
            
            # Find added values
            for name, data in current_values.items():
                if name not in baseline_values:
                    if key_id not in changes['added']:
                        changes['added'][key_id] = []
                    changes['added'][key_id].append({
                        'name': name,
                        'value': data['data'],
                        'type': data['type']
                    })
            
            # Find removed values
            for name in baseline_values:
                if name not in current_values:
                    if key_id not in changes['removed']:
                        changes['removed'][key_id] = []
                    changes['removed'][key_id].append({
                        'name': name,
                        'value': baseline_values[name]['data'],
                        'type': baseline_values[name]['type']
                    })
            
            # Find modified values
            for name in baseline_values:
                if name in current_values:
                    if current_values[name]['data'] != baseline_values[name]['data']:
                        if key_id not in changes['modified']:
                            changes['modified'][key_id] = []
                        changes['modified'][key_id].append({
                            'name': name,
                            'old_value': baseline_values[name]['data'],
                            'new_value': current_values[name]['data'],
                            'type': current_values[name]['type']
                        })
        
        return changes
    
    def has_changes(self) -> bool:
        """Check if there are any changes from baseline"""
        changes = self.compare_current_state()
        return bool(changes['added'] or changes['removed'] or changes['modified'])
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary of changes"""
        changes = self.compare_current_state()
        
        added_count = sum(len(v) for v in changes['added'].values())
        removed_count = sum(len(v) for v in changes['removed'].values())
        modified_count = sum(len(v) for v in changes['modified'].values())
        
        return {
            'added': added_count,
            'removed': removed_count,
            'modified': modified_count,
            'total_changes': added_count + removed_count + modified_count
        }


class ChangeDetector:
    """Detect suspicious or unauthorized registry changes"""
    
    # Suspicious patterns that may indicate malware
    SUSPICIOUS_PATTERNS = {
        'powershell': 'PowerShell execution',
        'cmd': 'Command line execution',
        'vbscript': 'VBScript execution',
        'wscript': 'Script execution',
        'certutil': 'Certificate utility abuse',
        'regsvcs': 'Registry service abuse',
        'regasm': 'Registry assembly abuse',
        'mshta': 'HTML application execution',
    }
    
    # High-risk registry paths
    HIGH_RISK_PATHS = [
        r'Software\Microsoft\Windows\CurrentVersion\Run',
        r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
        r'System\CurrentControlSet\Services',
    ]
    
    def __init__(self, comparator: BaselineComparator):
        self.comparator = comparator
        self.logger = logging.getLogger(__name__)
        self.alerts: List[Dict[str, Any]] = []
    
    def detect_changes(self) -> List[Dict[str, Any]]:
        """Detect suspicious changes and generate alerts"""
        self.alerts = []
        changes = self.comparator.compare_current_state()
        
        # Check added values
        for key_id, added_items in changes['added'].items():
            for item in added_items:
                if self._is_suspicious(key_id, item):
                    self.alerts.append(self._create_alert(
                        'added', key_id, item, 'suspicious'
                    ))
        
        # Check removed values
        for key_id, removed_items in changes['removed'].items():
            for item in removed_items:
                if self._is_critical_removal(key_id, item):
                    self.alerts.append(self._create_alert(
                        'removed', key_id, item, 'critical'
                    ))
        
        # Check modified values
        for key_id, modified_items in changes['modified'].items():
            for item in modified_items:
                if self._is_suspicious_modification(key_id, item):
                    self.alerts.append(self._create_alert(
                        'modified', key_id, item, 'suspicious'
                    ))
        
        return self.alerts
    
    def _is_suspicious(self, key_id: str, item: Dict[str, Any]) -> bool:
        """Check if a new value is suspicious"""
        value = str(item.get('value', '')).lower()
        
        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in value:
                return True
        
        # Check for high-risk paths
        for path in self.HIGH_RISK_PATHS:
            if path.lower() in key_id.lower():
                return True
        
        return False
    
    def _is_critical_removal(self, key_id: str, item: Dict[str, Any]) -> bool:
        """Check if a removal is critical"""
        # Removing security-related values is critical
        name = str(item.get('name', '')).lower()
        security_keywords = ['security', 'defender', 'antivirus', 'firewall', 'update']
        
        for keyword in security_keywords:
            if keyword in name:
                return True
        
        return False
    
    def _is_suspicious_modification(self, key_id: str, item: Dict[str, Any]) -> bool:
        """Check if a modification is suspicious"""
        # Changes to Run keys are suspicious
        for path in self.HIGH_RISK_PATHS:
            if path.lower() in key_id.lower():
                return True
        
        # Check if new value contains suspicious patterns
        new_value = str(item.get('new_value', '')).lower()
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in new_value:
                return True
        
        return False
    
    def _create_alert(self, change_type: str, key_id: str, 
                     item: Dict[str, Any], severity: str) -> Dict[str, Any]:
        """Create an alert for a detected change"""
        return {
            'timestamp': datetime.now().isoformat(),
            'change_type': change_type,
            'severity': severity,
            'registry_key': key_id,
            'value_name': item.get('name'),
            'old_value': item.get('old_value', item.get('value')),
            'new_value': item.get('new_value', item.get('value')),
            'value_type': item.get('type'),
            'description': self._get_alert_description(key_id, item, change_type)
        }
    
    def _get_alert_description(self, key_id: str, item: Dict[str, Any], 
                              change_type: str) -> str:
        """Generate a description for the alert"""
        name = item.get('name', 'Unknown')
        
        if change_type == 'added':
            return f"New value '{name}' added to {key_id}"
        elif change_type == 'removed':
            return f"Value '{name}' removed from {key_id}"
        else:  # modified
            return f"Value '{name}' modified in {key_id}"
    
    def save_alerts(self, filename: str = 'registry_alerts.json'):
        """Save alerts to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.alerts, f, indent=2, default=str)
            self.logger.info(f"Alerts saved to {filename}")
        except IOError as e:
            self.logger.error(f"Failed to save alerts: {e}")


class AlertManager:
    """Manages logging and alerting for the monitoring system"""
    
    def __init__(self, log_file: str = 'registry_monitor.log'):
        self.logger = self._setup_logger(log_file)
        self.alerts_log = []
    
    def _setup_logger(self, log_file: str) -> logging.Logger:
        """Setup comprehensive logging"""
        logger = logging.getLogger('registry_monitor')
        logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        logger.handlers = []
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_alert(self, alert: Dict[str, Any], level: str = 'WARNING'):
        """Log an alert"""
        log_level = getattr(logging, level.upper(), logging.WARNING)
        message = f"[{alert['severity'].upper()}] {alert['description']} - Key: {alert['registry_key']}"
        self.logger.log(log_level, message)
        self.alerts_log.append(alert)
    
    def log_baseline_created(self, key_count: int):
        """Log baseline creation"""
        self.logger.info(f"Baseline created for {key_count} registry keys")
    
    def log_comparison_started(self):
        """Log comparison start"""
        self.logger.info("Starting registry comparison with baseline")
    
    def log_comparison_complete(self, summary: Dict[str, int], alert_count: int):
        """Log comparison completion"""
        self.logger.info(
            f"Comparison complete - Added: {summary['added']}, "
            f"Removed: {summary['removed']}, Modified: {summary['modified']}, "
            f"Alerts: {alert_count}"
        )
    
    def get_alert_summary(self) -> Dict[str, int]:
        """Get summary of alerts by severity"""
        summary = {'critical': 0, 'suspicious': 0, 'info': 0}
        for alert in self.alerts_log:
            severity = alert.get('severity', 'info')
            if severity in summary:
                summary[severity] += 1
        return summary





def main():
    """Main entry point for the registry monitoring system"""
    print("Windows Registry Change Monitoring System v0.1.0")
    print("Starting registry monitor...")
    
    # Initialize monitor
    monitor = RegistryMonitor()
    
    # Add some critical Windows registry keys to monitor
    critical_keys = [
        ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Run'),
        ('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Run'),
    ]
    
    for hive, path in critical_keys:
        monitor.add_monitored_key(hive, path)
    
    print(f"Monitoring {len(monitor.monitored_keys)} registry keys...")
    
    # Create baseline
    monitor.create_baseline()
    monitor.save_baseline()
    
    # Initialize comparator and detector
    comparator = BaselineComparator(monitor)
    detector = ChangeDetector(comparator)
    
    # Check for changes
    summary = comparator.get_summary()
    print(f"Summary: {summary['total_changes']} changes detected")
    
    if summary['total_changes'] > 0:
        alerts = detector.detect_changes()
        print(f"Generated {len(alerts)} security alerts")
        detector.save_alerts()


if __name__ == "__main__":
    main()
