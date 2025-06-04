"""Splunk REST API Client for compliance checking"""

import splunklib.client as client
import splunklib.results as results
import requests
import urllib3
from typing import Dict, List, Optional, Any
import os
import xml.etree.ElementTree as ET


class SplunkAPIClient:
    """Handles all Splunk REST API interactions"""
    
    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Initialize Splunk SDK client
        self.service = None
        self._connect()
    
    def _connect(self):
        """Establish connection to Splunk"""
        try:
            self.service = client.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                verify=self.verify_ssl
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Splunk: {str(e)}")
    
    def test_connection(self) -> bool:
        """Test if the connection is valid"""
        try:
            # Try to get server info
            info = self.service.info()
            return True
        except:
            return False
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get Splunk server information"""
        info = self.service.info()
        return {
            'version': info.get('version', 'Unknown'),
            'build': info.get('build', 'Unknown'),
            'os': info.get('os_name', 'Unknown'),
            'server_name': info.get('serverName', 'Unknown')
        }
    
    def get_users(self) -> List[Dict[str, Any]]:
        """Get all users"""
        users = []
        for user in self.service.users:
            users.append({
                'name': user.name,
                'realname': user.realname,
                'email': user.email,
                'roles': user.roles,
                'type': user.type,
                'locked_out': user.locked_out
            })
        return users
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get specific user details"""
        try:
            user = self.service.users[username]
            return {
                'name': user.name,
                'realname': user.realname,
                'email': user.email,
                'roles': user.roles,
                'type': user.type,
                'locked_out': user.locked_out,
                'password_changed': user.content.get('password_changed_time', 'Unknown')
            }
        except:
            return None
    
    def get_roles(self) -> List[Dict[str, Any]]:
        """Get all roles"""
        roles = []
        for role in self.service.roles:
            roles.append({
                'name': role.name,
                'imported_roles': role.imported_roles,
                'capabilities': role.capabilities,
                'imported_capabilities': role.imported_capabilities
            })
        return roles
    
    def get_apps(self) -> List[Dict[str, Any]]:
        """Get all installed apps"""
        apps = []
        for app in self.service.apps:
            apps.append({
                'name': app.name,
                'label': app.label,
                'visible': app.visible,
                'disabled': app.disabled,
                'version': app.version
            })
        return apps
    
    def get_indexes(self) -> List[Dict[str, Any]]:
        """Get all indexes"""
        indexes = []
        for index in self.service.indexes:
            indexes.append({
                'name': index.name,
                'disabled': index.disabled,
                'total_size': index.content.get('totalEventCount', 0),
                'max_size': index.content.get('maxTotalDataSizeMB', 0),
                'home_path': index.content.get('homePath', ''),
                'cold_path': index.content.get('coldPath', ''),
                'frozen_path': index.content.get('frozenPath', '')
            })
        return indexes
    
    def get_config(self, conf_file: str, stanza: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration from a .conf file"""
        try:
            conf = self.service.confs[conf_file]
            
            if stanza:
                try:
                    stanza_obj = conf[stanza]
                    return dict(stanza_obj.content)
                except:
                    return {}
            else:
                # Return all stanzas
                result = {}
                for stanza_obj in conf:
                    result[stanza_obj.name] = dict(stanza_obj.content)
                return result
        except:
            return {}
    
    def check_file_exists(self, file_path: str) -> bool:
        """Check if a file exists on the Splunk server"""
        # This is a simplified check - in production, you'd need proper file system access
        # For now, we'll check common log locations
        if 'audit.log' in file_path:
            # Check if audit index exists and has data
            try:
                audit_index = self.service.indexes['_audit']
                return not audit_index.disabled
            except:
                return False
        return False
    
    def get_audit_config(self) -> Dict[str, Any]:
        """Get audit configuration"""
        try:
            audit_index = self.service.indexes['_audit']
            return {
                'enabled': not audit_index.disabled,
                'max_size': audit_index.content.get('maxTotalDataSizeMB', 0),
                'retention': audit_index.content.get('frozenTimePeriodInSecs', 0)
            }
        except:
            return {'enabled': False}
    
    def search(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """Execute a search query"""
        job = self.service.jobs.create(query, **kwargs)
        
        # Wait for job to complete
        while not job.is_done():
            pass
        
        # Get results
        results_reader = results.ResultsReader(job.results())
        search_results = []
        
        for result in results_reader:
            if isinstance(result, dict):
                search_results.append(result)
        
        job.cancel()
        return search_results
    
    def get_installed_apps_details(self) -> List[Dict[str, Any]]:
        """Get detailed information about installed apps"""
        apps = []
        for app in self.service.apps:
            app_details = {
                'name': app.name,
                'label': app.label,
                'version': app.version,
                'visible': app.visible,
                'disabled': app.disabled,
                'configured': app.configured,
                'author': app.content.get('author', 'Unknown'),
                'description': app.content.get('description', ''),
                'update_available': app.update()
            }
            apps.append(app_details)
        return apps
    
    def get_authentication_config(self) -> Dict[str, Any]:
        """Get authentication configuration"""
        auth_config = self.get_config('authentication.conf', 'splunk_auth')
        return auth_config
    
    def get_ssl_config(self) -> Dict[str, Any]:
        """Get SSL/TLS configuration"""
        server_ssl = self.get_config('server.conf', 'sslConfig')
        web_ssl = self.get_config('web.conf', 'settings')
        
        return {
            'server_ssl': server_ssl,
            'web_ssl': web_ssl
        }
    
    def get_deployment_client_config(self) -> Dict[str, Any]:
        """Get deployment client configuration"""
        return self.get_config('deploymentclient.conf')
    
    def check_license_status(self) -> Dict[str, Any]:
        """Check license status and compliance"""
        try:
            licenses = self.service.licenser.licenses
            license_info = {
                'valid': True,
                'licenses': []
            }
            
            for license in licenses:
                license_info['licenses'].append({
                    'type': license.type,
                    'status': license.status,
                    'expiration': license.expiration_time
                })
            
            return license_info
        except:
            return {'valid': False, 'licenses': []}