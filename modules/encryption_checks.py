"""Encryption and Data Protection compliance checks"""

from typing import Dict, List, Any
import re


class EncryptionChecker:
    """Handles encryption and data protection compliance checks"""
    
    def __init__(self, api_client, checks_config: Dict[str, Any]):
        self.api_client = api_client
        self.checks_config = checks_config
    
    def run_checks(self, verbose: bool = False) -> List[Dict[str, Any]]:
        """Run all encryption checks"""
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
            if check_id == 'SC-8-1':
                result.update(self._check_tls_config(config))
            elif check_id == 'SC-8-2':
                result.update(self._check_web_tls(config))
            elif check_id == 'SC-13-1':
                result.update(self._check_cipher_suites(config))
            elif check_id == 'SC-28-1':
                result.update(self._check_data_at_rest_encryption(config))
            else:
                result['status'] = 'SKIP'
                result['details'] = 'Check not implemented'
        
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Check failed with error: {str(e)}"
        
        return result
    
    def _check_tls_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check TLS configuration for Splunk management port"""
        ssl_config = self.api_client.get_ssl_config()
        server_ssl = ssl_config.get('server_ssl', {})
        
        if not server_ssl:
            return {
                'status': 'FAIL',
                'details': 'No SSL configuration found in server.conf',
                'remediation': 'Configure [sslConfig] stanza in server.conf'
            }
        
        issues = []
        settings = config.get('settings', {})
        
        # Check if SSL is enabled
        ssl_enabled = server_ssl.get('enableSplunkdSSL', 'false').lower()
        if ssl_enabled != 'true':
            issues.append('SSL/TLS is disabled for Splunk management port')
        
        # Check SSL versions
        ssl_versions = server_ssl.get('sslVersions', '')
        if ssl_versions:
            # Check for weak SSL versions
            blacklisted = settings.get('sslVersions', {}).get('blacklist', [])
            for bad_version in blacklisted:
                if bad_version.lower() in ssl_versions.lower():
                    issues.append(f'Weak SSL version enabled: {bad_version}')
            
            # Check for required versions
            if 'tls1.2' not in ssl_versions.lower():
                issues.append('TLS 1.2 not enabled')
        else:
            issues.append('SSL versions not specified')
        
        # Check certificate configuration
        if not server_ssl.get('serverCert'):
            issues.append('No server certificate configured')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Enable SSL with TLS 1.2+ only and configure proper certificates'
            }
        
        return {
            'status': 'PASS',
            'details': f'TLS properly configured with versions: {ssl_versions}'
        }
    
    def _check_web_tls(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check TLS configuration for web interface"""
        ssl_config = self.api_client.get_ssl_config()
        web_ssl = ssl_config.get('web_ssl', {})
        
        if not web_ssl:
            return {
                'status': 'FAIL',
                'details': 'No web SSL configuration found',
                'remediation': 'Configure SSL settings in web.conf'
            }
        
        issues = []
        
        # Check if SSL is enabled
        web_ssl_enabled = web_ssl.get('enableSplunkWebSSL', 'false').lower()
        if web_ssl_enabled != 'true':
            issues.append('HTTPS is disabled for web interface')
        
        # Check if HTTP is disabled
        http_port = web_ssl.get('httpport')
        if http_port and http_port != '0' and http_port.lower() != 'disabled':
            issues.append(f'Insecure HTTP is enabled on port {http_port}')
        
        # Check HSTS
        hsts = web_ssl.get('sendStrictTransportSecurityHeader', 'false').lower()
        if hsts != 'true':
            issues.append('HSTS header not enabled')
        
        # Check secure cookies
        secure_cookies = web_ssl.get('tools.sessions.secure', 'false').lower()
        if secure_cookies != 'true':
            issues.append('Secure cookie flag not set')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Enable HTTPS, disable HTTP, enable HSTS and secure cookies'
            }
        
        return {
            'status': 'PASS',
            'details': 'Web interface properly secured with HTTPS'
        }
    
    def _check_cipher_suites(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check cryptographic cipher suite configuration"""
        ssl_config = self.api_client.get_ssl_config()
        server_ssl = ssl_config.get('server_ssl', {})
        
        cipher_suite = server_ssl.get('cipherSuite', '')
        
        if not cipher_suite:
            return {
                'status': 'FAIL',
                'details': 'No cipher suite configured',
                'remediation': 'Configure cipherSuite in server.conf [sslConfig] stanza'
            }
        
        issues = []
        settings = config.get('settings', {})
        
        # Check for weak ciphers
        must_exclude = settings.get('cipherSuite', {}).get('must_exclude', [])
        for weak_cipher in must_exclude:
            if weak_cipher in cipher_suite:
                issues.append(f'Weak cipher enabled: {weak_cipher}')
        
        # Check for required strong ciphers
        must_include = settings.get('cipherSuite', {}).get('must_include', [])
        strong_cipher_found = False
        for strong_cipher in must_include:
            if strong_cipher in cipher_suite:
                strong_cipher_found = True
                break
        
        if not strong_cipher_found and must_include:
            issues.append('No strong ciphers configured')
        
        # Check for specific weak algorithms
        weak_patterns = ['DES', '3DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
        for pattern in weak_patterns:
            if pattern in cipher_suite:
                issues.append(f'Weak algorithm found: {pattern}')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Use only strong cipher suites (AES, ECDHE, RSA with key >= 2048)'
            }
        
        return {
            'status': 'PASS',
            'details': 'Strong cipher suites configured'
        }
    
    def _check_data_at_rest_encryption(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check encryption for data at rest"""
        issues = []
        encrypted_indexes = []
        unencrypted_indexes = []
        
        # Get all indexes
        indexes = self.api_client.get_indexes()
        
        for index in indexes:
            if index['name'].startswith('_'):  # Internal index
                # Check internal index encryption
                index_config = self.api_client.get_config('indexes.conf', index['name'])
                
                # Look for volume-based encryption
                volume = index_config.get('homePath', '').split('/')[0]
                if volume.startswith('volume:'):
                    volume_name = volume.replace('volume:', '')
                    volume_config = self.api_client.get_config('indexes.conf', f'volume:{volume_name}')
                    
                    if volume_config.get('path', '').startswith('$SPLUNK_DB'):
                        # Check server.conf for encryption settings
                        encrypt_config = self.api_client.get_config('server.conf', 'encryption')
                        if encrypt_config.get('encrypt', 'false').lower() == 'true':
                            encrypted_indexes.append(index['name'])
                        else:
                            unencrypted_indexes.append(index['name'])
                else:
                    unencrypted_indexes.append(index['name'])
            else:
                # Check user-defined index encryption
                index_config = self.api_client.get_config('indexes.conf', index['name'])
                
                # Simple check - in production, would need more sophisticated encryption detection
                if 'encrypt' in str(index_config).lower():
                    encrypted_indexes.append(index['name'])
                else:
                    unencrypted_indexes.append(index['name'])
        
        # Check KV store encryption
        kvstore_config = self.api_client.get_config('server.conf', 'kvstore')
        if kvstore_config:
            if kvstore_config.get('sslEnable', 'false').lower() != 'true':
                issues.append('KV store encryption not enabled')
        
        # Check secret storage
        if not self._check_secret_encryption():
            issues.append('Secret storage may not be encrypted')
        
        if unencrypted_indexes:
            critical_unencrypted = [idx for idx in unencrypted_indexes if idx in ['_audit', '_internal']]
            if critical_unencrypted:
                issues.append(f'Critical indexes not encrypted: {", ".join(critical_unencrypted)}')
            else:
                issues.append(f'{len(unencrypted_indexes)} indexes not encrypted')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Enable encryption for all indexes, KV store, and secrets'
            }
        
        return {
            'status': 'PASS',
            'details': f'Data at rest encryption enabled for {len(encrypted_indexes)} indexes'
        }
    
    def _check_secret_encryption(self) -> bool:
        """Check if secret storage is encrypted"""
        # Check for splunk.secret file and encryption
        # This is a simplified check - in production would need actual file system access
        
        server_config = self.api_client.get_config('server.conf', 'general')
        
        # Check if pass4SymmKey is configured (indicates secret encryption)
        if server_config.get('pass4SymmKey'):
            return True
        
        return False