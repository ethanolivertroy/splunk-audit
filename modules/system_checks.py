"""System Integrity and Configuration Management compliance checks"""

from typing import Dict, List, Any
import re
from datetime import datetime, timedelta
from packaging import version


class SystemChecker:
    """Handles system integrity and configuration management compliance checks"""
    
    def __init__(self, api_client, checks_config: Dict[str, Any]):
        self.api_client = api_client
        self.checks_config = checks_config
    
    def run_checks(self, verbose: bool = False) -> List[Dict[str, Any]]:
        """Run all system checks"""
        results = []
        
        for check_id, check_config in self.checks_config.items():
            if verbose:
                print(f"  Running {check_id}: {check_config['name']}")
            
            result = self._run_single_check(check_id, check_config)
            results.append(result)
        
        return results
    
    def _run_single_check(self, check_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single compliance check"""
        result = {
            'check_id': check_id,
            'name': config['name'],
            'description': config['description'],
            'nist_control': config['nist_control'],
            'severity': config['severity'],
            'status': 'UNKNOWN',
            'details': '',
            'remediation': ''
        }
        
        try:
            if check_id == 'CM-2-1':
                result.update(self._check_configuration_backup(config))
            elif check_id == 'CM-6-1':
                result.update(self._check_secure_configuration(config))
            elif check_id == 'CM-7-1':
                result.update(self._check_unnecessary_features(config))
            elif check_id == 'SI-2-1':
                result.update(self._check_splunk_version(config))
            elif check_id == 'SI-2-2':
                result.update(self._check_security_patches(config))
            else:
                result['status'] = 'SKIP'
                result['details'] = 'Check not implemented'
        
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Check failed with error: {str(e)}"
        
        return result
    
    def _check_configuration_backup(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check if configuration backups exist"""
        issues = []
        
        # Check for deployment server configuration
        deployment_config = self.api_client.get_deployment_client_config()
        
        if not deployment_config:
            issues.append('No deployment server configured for centralized management')
        
        # Check for configuration versioning
        # Look for common backup indicators
        try:
            # Search for backup-related logs
            search_query = 'index=_internal source=*splunkd.log* "backup" OR "archive" earliest=-7d | stats count'
            results = self.api_client.search(search_query)
            
            if results and len(results) > 0:
                backup_count = int(results[0].get('count', 0))
                if backup_count == 0:
                    issues.append('No backup activity found in last 7 days')
            else:
                issues.append('Could not verify backup activity')
        except:
            issues.append('Unable to search for backup activity')
        
        # Check for configuration export/archive apps
        apps = self.api_client.get_apps()
        backup_apps = [app for app in apps if any(term in app['name'].lower() 
                      for term in ['backup', 'config', 'archive', 'git'])]
        
        if not backup_apps and not deployment_config:
            issues.append('No configuration backup solution detected')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Implement configuration backups using deployment server, version control, or backup apps'
            }
        
        return {
            'status': 'PASS',
            'details': 'Configuration backup mechanisms detected'
        }
    
    def _check_secure_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check for secure configuration settings"""
        issues = []
        
        # Check various security configurations
        security_checks = [
            ('Scripted inputs', self._check_scripted_inputs()),
            ('Remote inputs', self._check_remote_inputs()),
            ('Development mode', self._check_development_mode()),
            ('Debug logging', self._check_debug_logging()),
            ('Anonymous access', self._check_anonymous_access())
        ]
        
        for check_name, check_result in security_checks:
            if not check_result:
                issues.append(f'{check_name} may be insecurely configured')
        
        # Check for default configurations
        server_info = self.api_client.get_server_info()
        
        # Check if running as root (Unix/Linux)
        if server_info.get('os', '').lower() in ['linux', 'unix', 'darwin']:
            # This is a simplified check - would need actual process info
            web_config = self.api_client.get_config('web.conf', 'settings')
            if web_config.get('root_endpoint', '') == '/':
                issues.append('Splunk may be running with elevated privileges')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Review and harden all security-relevant configurations'
            }
        
        return {
            'status': 'PASS',
            'details': 'Security configurations appear properly hardened'
        }
    
    def _check_unnecessary_features(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check for unnecessary features and apps"""
        issues = []
        unnecessary_apps = []
        
        # Get all apps
        apps = self.api_client.get_apps()
        
        # List of potentially unnecessary apps for production
        risky_apps = [
            ('sample', 'Sample data app'),
            ('testing', 'Testing app'),
            ('demo', 'Demo app'),
            ('tutorial', 'Tutorial app'),
            ('example', 'Example app'),
            ('gettingstarted', 'Getting started app')
        ]
        
        for app in apps:
            if not app['disabled']:
                app_name_lower = app['name'].lower()
                for risky_pattern, description in risky_apps:
                    if risky_pattern in app_name_lower:
                        unnecessary_apps.append(f"{app['name']} ({description})")
        
        if unnecessary_apps:
            issues.append(f'Potentially unnecessary apps enabled: {", ".join(unnecessary_apps)}')
        
        # Check for risky search commands enabled
        limits_config = self.api_client.get_config('limits.conf')
        
        risky_commands = ['script', 'run', 'runshellscript']
        for command in risky_commands:
            command_config = limits_config.get(command, {})
            if not command_config.get('disabled', 'false').lower() == 'true':
                issues.append(f'Risky search command enabled: {command}')
        
        # Check for unnecessary inputs
        inputs_config = self.api_client.get_config('inputs.conf')
        
        for stanza, settings in inputs_config.items():
            if stanza.startswith('script://'):
                if not settings.get('disabled', 'false').lower() == 'true':
                    issues.append(f'Scripted input enabled: {stanza}')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues[:3]) + (f' (+{len(issues)-3} more)' if len(issues) > 3 else ''),
                'remediation': 'Disable unnecessary apps, commands, and inputs'
            }
        
        return {
            'status': 'PASS',
            'details': 'No unnecessary features detected'
        }
    
    def _check_splunk_version(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check if Splunk version is supported"""
        server_info = self.api_client.get_server_info()
        current_version = server_info.get('version', 'Unknown')
        
        if current_version == 'Unknown':
            return {
                'status': 'ERROR',
                'details': 'Could not determine Splunk version',
                'remediation': 'Verify Splunk installation'
            }
        
        # Parse version
        try:
            ver = version.parse(current_version)
            min_version = version.parse(config.get('min_version', '8.2.0'))
            
            # Define supported versions (as of 2024)
            supported_versions = [
                version.parse('8.2.0'),  # Extended support
                version.parse('9.0.0'),  # Current
                version.parse('9.1.0'),  # Current
                version.parse('9.2.0'),  # Latest
            ]
            
            # Check if version is supported
            is_supported = any(ver >= sv for sv in supported_versions)
            
            if ver < min_version:
                return {
                    'status': 'FAIL',
                    'details': f'Splunk version {current_version} is below minimum required {min_version}',
                    'remediation': 'Upgrade to a supported Splunk version (8.2+ recommended)'
                }
            
            if not is_supported:
                return {
                    'status': 'WARN',
                    'details': f'Splunk version {current_version} may be unsupported',
                    'remediation': 'Verify version is still receiving security updates'
                }
            
            return {
                'status': 'PASS',
                'details': f'Running supported Splunk version {current_version}'
            }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'details': f'Could not parse version {current_version}: {str(e)}',
                'remediation': 'Manually verify Splunk version'
            }
    
    def _check_security_patches(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check for security patches and known vulnerabilities"""
        server_info = self.api_client.get_server_info()
        current_version = server_info.get('version', 'Unknown')
        build_number = server_info.get('build', 'Unknown')
        
        # Known vulnerable versions (simplified - in production would check CVE database)
        vulnerable_versions = {
            '8.2.0': 'CVE-2022-XXXXX - Upgrade to 8.2.12+',
            '8.2.1': 'CVE-2022-XXXXX - Upgrade to 8.2.12+',
            '9.0.0': 'CVE-2023-XXXXX - Upgrade to 9.0.5+',
            '9.0.1': 'CVE-2023-XXXXX - Upgrade to 9.0.5+',
        }
        
        issues = []
        
        # Check for known vulnerabilities
        if current_version in vulnerable_versions:
            issues.append(f'Known vulnerability in version {current_version}: {vulnerable_versions[current_version]}')
        
        # Check app vulnerabilities
        apps = self.api_client.get_installed_apps_details()
        
        for app in apps:
            if app.get('update_available'):
                issues.append(f'Update available for app: {app["name"]}')
        
        # Check for security-related logs
        try:
            # Search for security warnings
            search_query = '''index=_internal source=*splunkd.log* 
                            ("security" OR "vulnerability" OR "CVE") 
                            level=WARN OR level=ERROR 
                            earliest=-7d | stats count by message'''
            
            results = self.api_client.search(search_query)
            if results:
                for result in results[:3]:  # Limit to top 3
                    if int(result.get('count', 0)) > 0:
                        issues.append(f'Security warning in logs: {result.get("message", "Unknown")}')
        except:
            pass
        
        if issues:
            return {
                'status': 'FAIL' if any('CVE' in issue for issue in issues) else 'WARN',
                'details': '; '.join(issues[:3]) + (f' (+{len(issues)-3} more)' if len(issues) > 3 else ''),
                'remediation': 'Apply all security patches and update to latest stable version'
            }
        
        return {
            'status': 'PASS',
            'details': f'No known vulnerabilities detected for version {current_version} (build {build_number})'
        }
    
    # Helper methods for secure configuration checks
    def _check_scripted_inputs(self) -> bool:
        """Check if scripted inputs are properly restricted"""
        inputs_config = self.api_client.get_config('inputs.conf')
        
        for stanza in inputs_config:
            if stanza.startswith('script://'):
                if not inputs_config[stanza].get('disabled', 'false').lower() == 'true':
                    return False
        return True
    
    def _check_remote_inputs(self) -> bool:
        """Check if remote inputs are properly secured"""
        inputs_config = self.api_client.get_config('inputs.conf')
        
        # Check for splunktcp inputs without SSL
        for stanza in inputs_config:
            if stanza.startswith('splunktcp://'):
                if not inputs_config[stanza].get('encrypted', 'false').lower() == 'true':
                    return False
        return True
    
    def _check_development_mode(self) -> bool:
        """Check if development mode is disabled"""
        web_config = self.api_client.get_config('web.conf', 'settings')
        
        dev_mode = web_config.get('js_debug', 'false').lower()
        return dev_mode != 'true'
    
    def _check_debug_logging(self) -> bool:
        """Check if debug logging is disabled"""
        log_config = self.api_client.get_config('log.cfg')
        
        # Check for debug level logging
        for stanza, settings in log_config.items():
            if settings.get('level', '').upper() == 'DEBUG':
                return False
        return True
    
    def _check_anonymous_access(self) -> bool:
        """Check if anonymous access is disabled"""
        auth_config = self.api_client.get_config('authorize.conf')
        
        # Check for anonymous user role
        anon_role = auth_config.get('role_anonymous', {})
        if anon_role and not anon_role.get('disabled', 'false').lower() == 'true':
            return False
        
        return True