"""Configuration file parser for compliance checks"""

import yaml
import os
from typing import Dict, List, Any
from pathlib import Path


class ConfigParser:
    """Handles parsing of YAML configuration files"""
    
    def __init__(self, config_dir: str = None):
        if config_dir is None:
            # Get the directory where this script is located
            self.config_dir = Path(__file__).parent.parent / 'config'
        else:
            self.config_dir = Path(config_dir)
    
    def load_compliance_checks(self) -> Dict[str, Any]:
        """Load compliance check definitions from YAML"""
        checks_file = self.config_dir / 'checks.yaml'
        
        if not checks_file.exists():
            raise FileNotFoundError(f"Compliance checks file not found: {checks_file}")
        
        with open(checks_file, 'r') as f:
            data = yaml.safe_load(f)
        
        return data.get('compliance_checks', {})
    
    def load_severity_config(self) -> Dict[str, Any]:
        """Load severity mapping configuration"""
        severity_file = self.config_dir / 'severity_mapping.yaml'
        
        if not severity_file.exists():
            # Return default severity config if file not found
            return self._get_default_severity_config()
        
        with open(severity_file, 'r') as f:
            data = yaml.safe_load(f)
        
        return data
    
    def filter_checks_by_controls(self, checks: Dict[str, Any], controls: List[str]) -> Dict[str, Any]:
        """Filter checks by specified control families"""
        filtered = {}
        
        for category, category_checks in checks.items():
            filtered_category = {}
            
            for check_id, check_config in category_checks.items():
                nist_control = check_config.get('nist_control', '')
                # Check if control family matches (e.g., AC-2 matches AC)
                if any(nist_control.startswith(control) for control in controls):
                    filtered_category[check_id] = check_config
            
            if filtered_category:
                filtered[category] = filtered_category
        
        return filtered
    
    def filter_checks_by_standard(self, checks: Dict[str, Any], standard: str) -> Dict[str, Any]:
        """Filter checks by compliance standard"""
        filtered = {}
        
        # Map standard to baseline
        baseline_map = {
            'fedramp-low': 'low',
            'fedramp-moderate': 'moderate',
            'fedramp-high': 'high',
            'nist-800-53': None  # Include all
        }
        
        target_baseline = baseline_map.get(standard)
        
        for category, category_checks in checks.items():
            filtered_category = {}
            
            for check_id, check_config in category_checks.items():
                baselines = check_config.get('fedramp_baseline', [])
                
                # If NIST 800-53, include all checks
                if standard == 'nist-800-53':
                    filtered_category[check_id] = check_config
                # Otherwise, check if the target baseline is included
                elif target_baseline in baselines:
                    filtered_category[check_id] = check_config
            
            if filtered_category:
                filtered[category] = filtered_category
        
        return filtered
    
    def get_check_by_id(self, check_id: str) -> Dict[str, Any]:
        """Get a specific check by its ID"""
        checks = self.load_compliance_checks()
        
        for category, category_checks in checks.items():
            if check_id in category_checks:
                return category_checks[check_id]
        
        return None
    
    def get_checks_by_severity(self, severity: str) -> Dict[str, Any]:
        """Get all checks with a specific severity level"""
        checks = self.load_compliance_checks()
        filtered = {}
        
        for category, category_checks in checks.items():
            filtered_category = {}
            
            for check_id, check_config in category_checks.items():
                if check_config.get('severity') == severity:
                    filtered_category[check_id] = check_config
            
            if filtered_category:
                filtered[category] = filtered_category
        
        return filtered
    
    def _get_default_severity_config(self) -> Dict[str, Any]:
        """Return default severity configuration"""
        return {
            'severity_levels': {
                'critical': {
                    'score': 10,
                    'color': 'red',
                    'description': 'Critical security risk requiring immediate attention',
                    'sla_days': 1
                },
                'high': {
                    'score': 7,
                    'color': 'orange',
                    'description': 'High security risk requiring prompt attention',
                    'sla_days': 7
                },
                'medium': {
                    'score': 4,
                    'color': 'yellow',
                    'description': 'Medium security risk requiring planned remediation',
                    'sla_days': 30
                },
                'low': {
                    'score': 1,
                    'color': 'blue',
                    'description': 'Low security risk or best practice recommendation',
                    'sla_days': 90
                }
            },
            'scoring': {
                'pass_threshold': 80,
                'critical_failure_threshold': 1
            }
        }
    
    def validate_check_config(self, check_config: Dict[str, Any]) -> List[str]:
        """Validate a check configuration and return any errors"""
        errors = []
        required_fields = ['name', 'description', 'nist_control', 'severity', 'check_type']
        
        for field in required_fields:
            if field not in check_config:
                errors.append(f"Missing required field: {field}")
        
        # Validate severity
        valid_severities = ['critical', 'high', 'medium', 'low']
        if check_config.get('severity') not in valid_severities:
            errors.append(f"Invalid severity: {check_config.get('severity')}")
        
        # Validate check type
        valid_check_types = ['api', 'config', 'file_exists', 'file_permissions', 
                           'version_check', 'patch_check', 'audit_content', 
                           'index_encryption', 'multiple_configs', 'backup_exists']
        
        if check_config.get('check_type') not in valid_check_types:
            errors.append(f"Invalid check_type: {check_config.get('check_type')}")
        
        return errors