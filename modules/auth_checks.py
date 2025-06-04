"""Authentication and Access Control compliance checks"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
import re


class AuthenticationChecker:
    """Handles authentication and access control compliance checks"""
    
    def __init__(self, api_client, checks_config: Dict[str, Any]):
        self.api_client = api_client
        self.checks_config = checks_config
    
    def run_checks(self, verbose: bool = False) -> List[Dict[str, Any]]:
        """Run all authentication checks"""
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
            if check_id == 'AC-2-1':
                result.update(self._check_default_admin(config))
            elif check_id == 'AC-2-2':
                result.update(self._check_service_accounts(config))
            elif check_id == 'AC-7-1':
                result.update(self._check_lockout_policy(config))
            elif check_id == 'AC-11-1':
                result.update(self._check_session_timeout(config))
            elif check_id == 'IA-2-1':
                result.update(self._check_mfa(config))
            elif check_id == 'IA-5-1':
                result.update(self._check_password_complexity(config))
            else:
                result['status'] = 'SKIP'
                result['details'] = 'Check not implemented'
        
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Check failed with error: {str(e)}"
        
        return result
    
    def _check_default_admin(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check if default admin account is properly secured"""
        admin_user = self.api_client.get_user('admin')
        
        if not admin_user:
            return {
                'status': 'PASS',
                'details': 'Default admin account not found (disabled or removed)'
            }
        
        # Check if admin is locked out (good)
        if admin_user.get('locked_out'):
            return {
                'status': 'PASS',
                'details': 'Default admin account is locked out'
            }
        
        # Check password change time
        password_changed = admin_user.get('password_changed', 'Unknown')
        
        if password_changed == 'Unknown' or password_changed == '':
            return {
                'status': 'FAIL',
                'details': 'Default admin password has never been changed',
                'remediation': 'Change the default admin password immediately or disable the account'
            }
        
        try:
            # Check if password was changed recently (within last 90 days)
            change_time = datetime.fromtimestamp(float(password_changed))
            days_since_change = (datetime.now() - change_time).days
            
            if days_since_change > 90:
                return {
                    'status': 'FAIL',
                    'details': f'Admin password last changed {days_since_change} days ago',
                    'remediation': 'Change admin password (passwords should be rotated every 90 days)'
                }
            else:
                return {
                    'status': 'PASS',
                    'details': f'Admin password changed {days_since_change} days ago'
                }
        except:
            return {
                'status': 'WARN',
                'details': 'Could not determine password change date',
                'remediation': 'Verify admin password has been changed from default'
            }
    
    def _check_service_accounts(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check service account management"""
        users = self.api_client.get_users()
        service_accounts = []
        issues = []
        
        for user in users:
            # Identify potential service accounts (no email, specific naming patterns)
            if (not user.get('email') or 
                user['name'].startswith('svc_') or 
                user['name'].startswith('service_') or
                user['name'].endswith('_service')):
                
                service_accounts.append(user['name'])
                
                # Check for issues
                if 'admin' in user.get('roles', []):
                    issues.append(f"{user['name']} has admin role (violates least privilege)")
                
                if user.get('locked_out'):
                    issues.append(f"{user['name']} is locked out (may impact services)")
        
        if not service_accounts:
            return {
                'status': 'PASS',
                'details': 'No service accounts detected'
            }
        
        if issues:
            return {
                'status': 'FAIL',
                'details': f'Found {len(service_accounts)} service accounts with issues: ' + '; '.join(issues),
                'remediation': 'Review service account permissions and ensure least privilege principle'
            }
        
        return {
            'status': 'PASS',
            'details': f'Found {len(service_accounts)} service accounts, all properly configured'
        }
    
    def _check_lockout_policy(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check account lockout configuration"""
        auth_config = self.api_client.get_authentication_config()
        
        if not auth_config:
            return {
                'status': 'FAIL',
                'details': 'Could not retrieve authentication configuration',
                'remediation': 'Ensure authentication.conf is properly configured'
            }
        
        settings = config.get('settings', {})
        issues = []
        
        # Check lockout attempts
        lockout_attempts = auth_config.get('lockoutAttempts')
        if not lockout_attempts:
            issues.append('Account lockout is not configured')
        else:
            attempts = int(lockout_attempts)
            min_val = settings.get('lockoutAttempts', {}).get('min_value', 3)
            max_val = settings.get('lockoutAttempts', {}).get('max_value', 5)
            
            if attempts < min_val or attempts > max_val:
                issues.append(f'Lockout attempts ({attempts}) should be between {min_val} and {max_val}')
        
        # Check lockout duration
        lockout_duration = auth_config.get('lockoutDuration')
        if not lockout_duration:
            issues.append('Lockout duration is not configured')
        else:
            duration = int(lockout_duration)
            min_duration = settings.get('lockoutDuration', {}).get('min_value', 900)
            
            if duration < min_duration:
                issues.append(f'Lockout duration ({duration}s) should be at least {min_duration}s')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Configure lockoutAttempts=3 and lockoutDuration=900 in authentication.conf'
            }
        
        return {
            'status': 'PASS',
            'details': f'Account lockout configured: {lockout_attempts} attempts, {lockout_duration}s duration'
        }
    
    def _check_session_timeout(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check session timeout configuration"""
        web_config = self.api_client.get_config('web.conf', 'settings')
        
        if not web_config:
            return {
                'status': 'FAIL',
                'details': 'Could not retrieve web configuration',
                'remediation': 'Ensure web.conf is properly configured'
            }
        
        # Check session timeout
        timeout = web_config.get('tools.sessions.timeout')
        ui_timeout = web_config.get('ui_inactivity_timeout')
        
        issues = []
        max_timeout = config.get('settings', {}).get('tools.sessions.timeout', {}).get('max_value', 15)
        
        if not timeout:
            issues.append('Session timeout not configured')
        else:
            timeout_val = int(timeout)
            if timeout_val > max_timeout:
                issues.append(f'Session timeout ({timeout_val} min) exceeds maximum ({max_timeout} min)')
        
        if not ui_timeout:
            issues.append('UI inactivity timeout not configured')
        else:
            ui_timeout_val = int(ui_timeout)
            if ui_timeout_val > max_timeout * 60:  # Convert to seconds
                issues.append(f'UI timeout ({ui_timeout_val}s) exceeds maximum ({max_timeout * 60}s)')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': f'Set tools.sessions.timeout={max_timeout} and ui_inactivity_timeout={max_timeout * 60} in web.conf'
            }
        
        return {
            'status': 'PASS',
            'details': f'Session timeout properly configured: {timeout} minutes'
        }
    
    def _check_mfa(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check multi-factor authentication configuration"""
        auth_config = self.api_client.get_authentication_config()
        
        # Check for SAML configuration
        saml_config = self.api_client.get_config('authentication.conf', 'authentication')
        
        mfa_indicators = []
        
        # Check for SAML (often includes MFA)
        if saml_config and saml_config.get('authType') == 'SAML':
            mfa_indicators.append('SAML authentication configured')
        
        # Check for Duo integration
        duo_config = self.api_client.get_config('authentication.conf', 'duo')
        if duo_config:
            mfa_indicators.append('Duo Security integration found')
        
        # Check for RSA SecurID
        rsa_config = self.api_client.get_config('authentication.conf', 'SecurID')
        if rsa_config:
            mfa_indicators.append('RSA SecurID integration found')
        
        if not mfa_indicators:
            return {
                'status': 'FAIL',
                'details': 'No multi-factor authentication configured',
                'remediation': 'Implement MFA using SAML, Duo Security, or other supported MFA solution'
            }
        
        return {
            'status': 'PASS',
            'details': 'MFA configured: ' + ', '.join(mfa_indicators)
        }
    
    def _check_password_complexity(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check password complexity requirements"""
        auth_config = self.api_client.get_authentication_config()
        
        if not auth_config:
            return {
                'status': 'FAIL',
                'details': 'Could not retrieve authentication configuration',
                'remediation': 'Ensure authentication.conf is properly configured'
            }
        
        settings = config.get('settings', {})
        issues = []
        
        # Check each password requirement
        checks = {
            'minPasswordLength': ('Minimum password length', 12),
            'minPasswordUppercase': ('Uppercase letters required', 1),
            'minPasswordLowercase': ('Lowercase letters required', 1),
            'minPasswordDigit': ('Digits required', 1),
            'minPasswordSpecial': ('Special characters required', 1)
        }
        
        for setting, (description, min_value) in checks.items():
            value = auth_config.get(setting)
            
            if not value:
                issues.append(f'{description} not configured')
            else:
                val = int(value)
                if val < min_value:
                    issues.append(f'{description}: {val} (minimum: {min_value})')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': 'Password complexity issues: ' + '; '.join(issues),
                'remediation': 'Configure password requirements in authentication.conf [splunk_auth] stanza'
            }
        
        return {
            'status': 'PASS',
            'details': 'Password complexity requirements properly configured'
        }