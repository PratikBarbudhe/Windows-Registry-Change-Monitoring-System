"""
Comprehensive tests for Windows Registry Change Monitoring System
"""
import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Import classes from monitor module
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from monitor import RegistryReader, RegistryMonitor, BaselineComparator, ChangeDetector


class TestRegistryReader:
    """Test suite for RegistryReader class"""
    
    def test_initialization(self):
        """Test RegistryReader initialization"""
        reader = RegistryReader()
        assert reader.hive_map is not None
        assert 'HKLM' in reader.hive_map
        assert 'HKCU' in reader.hive_map
    
    @patch('monitor.winreg.OpenKey')
    @patch('monitor.winreg.EnumValue')
    @patch('monitor.winreg.CloseKey')
    def test_get_registry_values_success(self, mock_close, mock_enum, mock_open):
        """Test successful registry value retrieval"""
        mock_key = Mock()
        mock_open.return_value = mock_key
        mock_enum.side_effect = [
            ('Value1', 'Data1', 1),
            ('Value2', 'Data2', 1),
            OSError()
        ]
        
        reader = RegistryReader()
        values = reader.get_registry_values('HKLM', 'Software\\Test')
        
        assert len(values) == 2
        assert 'Value1' in values
        assert 'Value2' in values
        assert values['Value1']['data'] == 'Data1'
    
    @patch('monitor.winreg.OpenKey')
    def test_get_registry_values_permission_denied(self, mock_open):
        """Test handling of permission denied"""
        mock_open.side_effect = PermissionError()
        
        reader = RegistryReader()
        values = reader.get_registry_values('HKLM', 'Software\\Protected')
        
        assert values == {}
    
    @patch('monitor.winreg.OpenKey')
    def test_get_registry_values_not_found(self, mock_open):
        """Test handling of key not found"""
        mock_open.side_effect = FileNotFoundError()
        
        reader = RegistryReader()
        values = reader.get_registry_values('HKLM', 'Software\\NotFound')
        
        assert values == {}


class TestRegistryMonitor:
    """Test suite for RegistryMonitor class"""
    
    def test_initialization(self):
        """Test RegistryMonitor initialization"""
        monitor = RegistryMonitor()
        assert monitor.monitored_keys == []
        assert monitor.baseline == {}
        assert monitor.logger is not None
    
    def test_add_monitored_key(self):
        """Test adding a monitored key"""
        monitor = RegistryMonitor()
        monitor.add_monitored_key('HKLM', 'Software\\Test')
        
        assert ('HKLM', 'Software\\Test') in monitor.monitored_keys
    
    def test_add_monitored_key_no_duplicate(self):
        """Test that duplicate keys are not added"""
        monitor = RegistryMonitor()
        monitor.add_monitored_key('HKLM', 'Software\\Test')
        monitor.add_monitored_key('HKLM', 'Software\\Test')
        
        assert monitor.monitored_keys.count(('HKLM', 'Software\\Test')) == 1
    
    @patch.object(RegistryReader, 'get_registry_values')
    def test_create_baseline(self, mock_get_values):
        """Test baseline creation"""
        mock_get_values.return_value = {'Value1': {'data': 'Data1', 'type': 1}}
        
        monitor = RegistryMonitor()
        monitor.add_monitored_key('HKLM', 'Software\\Test')
        baseline = monitor.create_baseline()
        
        assert 'HKLM\\Software\\Test' in baseline
        assert 'values' in baseline['HKLM\\Software\\Test']
        assert 'timestamp' in baseline['HKLM\\Software\\Test']
    
    def test_save_baseline(self):
        """Test baseline file saving"""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor = RegistryMonitor()
            monitor.baseline = {'test': {'values': {}, 'timestamp': '2026-04-29'}}
            
            filepath = os.path.join(tmpdir, 'baseline.json')
            monitor.save_baseline(filepath)
            
            assert os.path.exists(filepath)
            with open(filepath, 'r') as f:
                data = json.load(f)
            assert 'test' in data
    
    def test_load_baseline(self):
        """Test baseline file loading"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a baseline file
            baseline_data = {'test': {'values': {}, 'timestamp': '2026-04-29'}}
            filepath = os.path.join(tmpdir, 'baseline.json')
            with open(filepath, 'w') as f:
                json.dump(baseline_data, f)
            
            # Load it
            monitor = RegistryMonitor()
            monitor.load_baseline(filepath)
            
            assert 'test' in monitor.baseline


class TestBaselineComparator:
    """Test suite for BaselineComparator class"""
    
    def test_initialization(self):
        """Test BaselineComparator initialization"""
        monitor = RegistryMonitor()
        comparator = BaselineComparator(monitor)
        
        assert comparator.monitor is monitor
        assert comparator.logger is not None
    
    @patch.object(RegistryReader, 'get_registry_values')
    def test_compare_current_state_added(self, mock_get_values):
        """Test detection of added values"""
        monitor = RegistryMonitor()
        monitor.baseline = {
            'HKLM\\Software\\Test': {
                'values': {'Value1': {'data': 'Data1', 'type': 1}},
                'timestamp': '2026-04-29'
            }
        }
        
        # Current state has an additional value
        mock_get_values.return_value = {
            'Value1': {'data': 'Data1', 'type': 1},
            'Value2': {'data': 'Data2', 'type': 1}
        }
        
        comparator = BaselineComparator(monitor)
        changes = comparator.compare_current_state()
        
        assert 'HKLM\\Software\\Test' in changes['added']
        assert len(changes['added']['HKLM\\Software\\Test']) == 1
    
    @patch.object(RegistryReader, 'get_registry_values')
    def test_compare_current_state_removed(self, mock_get_values):
        """Test detection of removed values"""
        monitor = RegistryMonitor()
        monitor.baseline = {
            'HKLM\\Software\\Test': {
                'values': {
                    'Value1': {'data': 'Data1', 'type': 1},
                    'Value2': {'data': 'Data2', 'type': 1}
                },
                'timestamp': '2026-04-29'
            }
        }
        
        # Current state has fewer values
        mock_get_values.return_value = {'Value1': {'data': 'Data1', 'type': 1}}
        
        comparator = BaselineComparator(monitor)
        changes = comparator.compare_current_state()
        
        assert 'HKLM\\Software\\Test' in changes['removed']
        assert len(changes['removed']['HKLM\\Software\\Test']) == 1
    
    @patch.object(RegistryReader, 'get_registry_values')
    def test_compare_current_state_modified(self, mock_get_values):
        """Test detection of modified values"""
        monitor = RegistryMonitor()
        monitor.baseline = {
            'HKLM\\Software\\Test': {
                'values': {'Value1': {'data': 'OldData', 'type': 1}},
                'timestamp': '2026-04-29'
            }
        }
        
        # Current state has modified value
        mock_get_values.return_value = {'Value1': {'data': 'NewData', 'type': 1}}
        
        comparator = BaselineComparator(monitor)
        changes = comparator.compare_current_state()
        
        assert 'HKLM\\Software\\Test' in changes['modified']
        assert changes['modified']['HKLM\\Software\\Test'][0]['old_value'] == 'OldData'
        assert changes['modified']['HKLM\\Software\\Test'][0]['new_value'] == 'NewData'
    
    @patch.object(RegistryReader, 'get_registry_values')
    def test_has_changes(self, mock_get_values):
        """Test detection of any changes"""
        monitor = RegistryMonitor()
        monitor.baseline = {
            'HKLM\\Software\\Test': {
                'values': {'Value1': {'data': 'Data1', 'type': 1}},
                'timestamp': '2026-04-29'
            }
        }
        
        mock_get_values.return_value = {'Value2': {'data': 'Data2', 'type': 1}}
        
        comparator = BaselineComparator(monitor)
        assert comparator.has_changes()
    
    @patch.object(RegistryReader, 'get_registry_values')
    def test_get_summary(self, mock_get_values):
        """Test change summary"""
        monitor = RegistryMonitor()
        monitor.baseline = {
            'HKLM\\Software\\Test': {
                'values': {'Value1': {'data': 'Data1', 'type': 1}},
                'timestamp': '2026-04-29'
            }
        }
        
        mock_get_values.return_value = {
            'Value1': {'data': 'ModifiedData', 'type': 1},
            'Value2': {'data': 'Data2', 'type': 1}
        }
        
        comparator = BaselineComparator(monitor)
        summary = comparator.get_summary()
        
        assert summary['added'] == 1
        assert summary['modified'] == 1
        assert summary['removed'] == 0
        assert summary['total_changes'] == 2


class TestChangeDetector:
    """Test suite for ChangeDetector class"""
    
    def test_initialization(self):
        """Test ChangeDetector initialization"""
        monitor = RegistryMonitor()
        comparator = BaselineComparator(monitor)
        detector = ChangeDetector(comparator)
        
        assert detector.comparator is comparator
        assert detector.logger is not None
        assert detector.alerts == []
    
    @patch.object(BaselineComparator, 'compare_current_state')
    def test_detect_suspicious_addition(self, mock_compare):
        """Test detection of suspicious additions"""
        changes = {
            'added': {
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': [
                    {'name': 'malware', 'value': 'powershell.exe -Command ...', 'type': 1}
                ]
            },
            'removed': {},
            'modified': {},
            'timestamp': '2026-04-29'
        }
        mock_compare.return_value = changes
        
        monitor = RegistryMonitor()
        comparator = BaselineComparator(monitor)
        detector = ChangeDetector(comparator)
        
        alerts = detector.detect_changes()
        assert len(alerts) > 0
        assert alerts[0]['severity'] == 'suspicious'
    
    @patch.object(BaselineComparator, 'compare_current_state')
    def test_detect_critical_removal(self, mock_compare):
        """Test detection of critical removals"""
        changes = {
            'added': {},
            'removed': {
                'HKLM\\Software\\Test': [
                    {'name': 'windows_defender_setting', 'value': 'enabled', 'type': 1}
                ]
            },
            'modified': {},
            'timestamp': '2026-04-29'
        }
        mock_compare.return_value = changes
        
        monitor = RegistryMonitor()
        comparator = BaselineComparator(monitor)
        detector = ChangeDetector(comparator)
        
        alerts = detector.detect_changes()
        assert len(alerts) > 0
    
    def test_save_alerts(self):
        """Test saving alerts to file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            monitor = RegistryMonitor()
            comparator = BaselineComparator(monitor)
            detector = ChangeDetector(comparator)
            
            detector.alerts = [{
                'timestamp': '2026-04-29',
                'change_type': 'added',
                'severity': 'suspicious',
                'registry_key': 'HKLM\\Software\\Test',
                'value_name': 'test',
                'description': 'Test alert'
            }]
            
            filepath = os.path.join(tmpdir, 'alerts.json')
            detector.save_alerts(filepath)
            
            assert os.path.exists(filepath)
            with open(filepath, 'r') as f:
                data = json.load(f)
            assert len(data) == 1


class TestIntegration:
    """Integration tests for the entire system"""
    
    @patch.object(RegistryReader, 'get_registry_values')
    def test_full_workflow(self, mock_get_values):
        """Test complete monitoring workflow"""
        # Initial state
        mock_get_values.return_value = {
            'Value1': {'data': 'Data1', 'type': 1}
        }
        
        # Create baseline
        monitor = RegistryMonitor()
        monitor.add_monitored_key('HKLM', 'Software\\Test')
        monitor.create_baseline()
        
        # Simulate change
        mock_get_values.return_value = {
            'Value1': {'data': 'Data1', 'type': 1},
            'Value2': {'data': 'powershell.exe', 'type': 1}
        }
        
        # Compare and detect
        comparator = BaselineComparator(monitor)
        detector = ChangeDetector(comparator)
        alerts = detector.detect_changes()
        
        # Verify detection
        assert len(alerts) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
