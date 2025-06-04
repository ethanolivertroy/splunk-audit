"""Audit and Logging compliance checks"""

from typing import Dict, List, Any
import os
import re


class AuditChecker:
    """Handles audit and logging compliance checks"""
    
    def __init__(self, api_client, checks_config: Dict[str, Any]):
        self.api_client = api_client
        self.checks_config = checks_config
    
    def run_checks(self, verbose: bool = False) -> List[Dict[str, Any]]:
        """Run all audit checks"""
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
            if check_id == 'AU-2-1':
                result.update(self._check_audit_logging_enabled(config))
            elif check_id == 'AU-3-1':
                result.update(self._check_audit_content(config))
            elif check_id == 'AU-4-1':
                result.update(self._check_audit_storage(config))
            elif check_id == 'AU-9-1':
                result.update(self._check_audit_protection(config))
            elif check_id == 'AU-12-1':
                result.update(self._check_audit_generation(config))
            else:
                result['status'] = 'SKIP'
                result['details'] = 'Check not implemented'
        
        except Exception as e:
            result['status'] = 'ERROR'
            result['details'] = f"Check failed with error: {str(e)}"
        
        return result
    
    def _check_audit_logging_enabled(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check if audit logging is enabled"""
        audit_config = self.api_client.get_audit_config()
        
        if not audit_config.get('enabled', False):
            return {
                'status': 'FAIL',
                'details': 'Audit logging is disabled',
                'remediation': 'Enable the _audit index and ensure audit events are being collected'
            }
        
        # Check if audit index is receiving data
        try:
            # Search for recent audit events
            search_query = 'index=_audit earliest=-1h | stats count'
            results = self.api_client.search(search_query)
            
            if results and len(results) > 0:
                count = int(results[0].get('count', 0))
                if count == 0:
                    return {
                        'status': 'FAIL',
                        'details': 'Audit index enabled but no recent events found',
                        'remediation': 'Verify audit logging is properly configured and events are being generated'
                    }
                else:
                    return {
                        'status': 'PASS',
                        'details': f'Audit logging enabled with {count} events in the last hour'
                    }
            else:
                return {
                    'status': 'WARN',
                    'details': 'Could not verify audit event collection',
                    'remediation': 'Manually verify audit events are being collected'
                }
        except Exception as e:
            return {
                'status': 'WARN',
                'details': f'Could not search audit index: {str(e)}',
                'remediation': 'Ensure proper permissions to search _audit index'
            }
    
    def _check_audit_content(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check if audit logs contain required information"""
        required_fields = config.get('required_fields', [])
        
        try:
            # Get sample audit events
            search_query = 'index=_audit earliest=-1h | head 10'
            results = self.api_client.search(search_query)
            
            if not results:
                return {
                    'status': 'WARN',
                    'details': 'No audit events found to verify content',
                    'remediation': 'Ensure audit events are being generated'
                }
            
            # Check if required fields are present
            missing_fields = []
            for field in required_fields:
                field_found = False
                for event in results:
                    if field in event:
                        field_found = True
                        break
                
                if not field_found:
                    missing_fields.append(field)
            
            if missing_fields:
                return {
                    'status': 'FAIL',
                    'details': f'Audit logs missing required fields: {", ".join(missing_fields)}',
                    'remediation': 'Configure audit logging to include all required fields'
                }
            
            return {
                'status': 'PASS',
                'details': 'Audit logs contain all required fields'
            }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'details': f'Could not verify audit content: {str(e)}',
                'remediation': 'Check audit index permissions and configuration'
            }
    
    def _check_audit_storage(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check audit storage capacity configuration"""
        try:
            indexes = self.api_client.get_indexes()
            audit_index = next((idx for idx in indexes if idx['name'] == '_audit'), None)
            
            if not audit_index:
                return {
                    'status': 'FAIL',
                    'details': 'Audit index not found',
                    'remediation': 'Create and configure the _audit index'
                }
            
            # Check storage settings
            max_size = audit_index.get('max_size', 0)
            min_required = config.get('settings', {}).get('maxTotalDataSizeMB', {}).get('min_value', 10240)
            
            if max_size < min_required:
                return {
                    'status': 'FAIL',
                    'details': f'Audit storage capacity ({max_size}MB) below minimum ({min_required}MB)',
                    'remediation': f'Increase maxTotalDataSizeMB for _audit index to at least {min_required}MB'
                }
            
            # Check retention
            audit_config = self.api_client.get_config('indexes.conf', '_audit')
            retention = audit_config.get('frozenTimePeriodInSecs', '0')
            
            try:
                retention_days = int(retention) / 86400  # Convert to days
                if retention_days < 90:  # FedRAMP typically requires 90 days minimum
                    return {
                        'status': 'WARN',
                        'details': f'Audit retention period ({retention_days:.0f} days) may be insufficient',
                        'remediation': 'Consider increasing frozenTimePeriodInSecs to at least 7776000 (90 days)'
                    }
            except:
                pass
            
            return {
                'status': 'PASS',
                'details': f'Audit storage properly configured with {max_size}MB capacity'
            }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'details': f'Could not check audit storage: {str(e)}',
                'remediation': 'Verify index configuration access'
            }
    
    def _check_audit_protection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check audit log protection mechanisms"""
        issues = []
        
        # Check if audit logs are being forwarded (backup/protection)
        outputs_config = self.api_client.get_config('outputs.conf')
        
        if not outputs_config:
            issues.append('No log forwarding configured for audit protection')
        else:
            # Check for indexer clustering or forwarding
            has_forwarding = False
            for stanza, settings in outputs_config.items():
                if stanza.startswith('tcpout:') or stanza.startswith('indexer_discovery:'):
                    has_forwarding = True
                    break
            
            if not has_forwarding:
                issues.append('Audit logs not being forwarded for protection')
        
        # Check SSL/TLS for log forwarding
        if outputs_config:
            for stanza, settings in outputs_config.items():
                if stanza.startswith('tcpout:'):
                    if not settings.get('useSSL', '').lower() == 'true':
                        issues.append(f'Log forwarding {stanza} not using SSL/TLS')
        
        # Check audit index replication
        server_config = self.api_client.get_config('server.conf', 'clustering')
        if server_config and server_config.get('mode') == 'master':
            replication_factor = server_config.get('replication_factor', '1')
            if int(replication_factor) < 2:
                issues.append('Audit logs not replicated (replication_factor < 2)')
        
        if issues:
            return {
                'status': 'FAIL',
                'details': '; '.join(issues),
                'remediation': 'Implement log forwarding with SSL/TLS and ensure proper replication'
            }
        
        return {
            'status': 'PASS',
            'details': 'Audit logs are properly protected'
        }
    
    def _check_audit_generation(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Check that all required events are being audited"""
        required_events = [
            ('Authentication', 'action=login OR action=logout'),
            ('Authorization changes', 'action=edit_user OR action=edit_roles'),
            ('Configuration changes', 'action=edit_*'),
            ('Search activity', 'action=search'),
            ('Data access', 'action=export OR action=download')
        ]
        
        missing_events = []
        event_counts = {}
        
        for event_type, search_filter in required_events:
            try:
                query = f'index=_audit {search_filter} earliest=-24h | stats count'
                results = self.api_client.search(query)
                
                if results and len(results) > 0:
                    count = int(results[0].get('count', 0))
                    event_counts[event_type] = count
                    
                    if count == 0:
                        missing_events.append(event_type)
                else:
                    missing_events.append(event_type)
                    
            except Exception as e:
                missing_events.append(f'{event_type} (error: {str(e)})')
        
        if missing_events:
            return {
                'status': 'FAIL',
                'details': f'No audit events found for: {", ".join(missing_events)}',
                'remediation': 'Ensure all security-relevant events are being audited'
            }
        
        # Create summary of event counts
        summary = ', '.join([f'{k}: {v}' for k, v in event_counts.items()])
        
        return {
            'status': 'PASS',
            'details': f'All required events are being audited. 24h counts: {summary}'
        }