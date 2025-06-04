# NIST 800-53 to Splunk Configuration Mapping

## Access Control (AC)

### AC-2: Account Management
**Splunk Configurations to Check:**
- `authentication.conf`: User account settings
- `authorize.conf`: Role definitions and capabilities
- REST API: `/services/authentication/users`
- Check for service accounts, default accounts, inactive accounts

### AC-3: Access Enforcement
**Splunk Configurations to Check:**
- `authorize.conf`: Role-based access control
- `indexes.conf`: Index-level permissions
- App-level permissions in `local.meta` or `default.meta`

### AC-7: Unsuccessful Logon Attempts
**Splunk Configurations to Check:**
- `authentication.conf`: `lockoutAttempts`, `lockoutDuration`
- `audit.log`: Failed authentication events

### AC-11: Session Lock
**Splunk Configurations to Check:**
- `web.conf`: `tools.sessions.timeout`
- `ui-inactivity-timeout` in `web.conf`

## Audit and Accountability (AU)

### AU-2: Audit Events
**Splunk Configurations to Check:**
- `audit.log` existence and configuration
- `inputs.conf`: Audit log monitoring
- `outputs.conf`: Audit log forwarding

### AU-3: Content of Audit Records
**Splunk Configurations to Check:**
- Audit event format and fields
- Timestamp precision
- User identification in logs

### AU-4: Audit Storage Capacity
**Splunk Configurations to Check:**
- `indexes.conf`: `maxTotalDataSizeMB`, `maxGlobalDataSizeMB`
- Disk space monitoring
- Index retention policies

### AU-9: Protection of Audit Information
**Splunk Configurations to Check:**
- File permissions on audit logs
- Log forwarding encryption
- Index encryption settings

## Configuration Management (CM)

### CM-2: Baseline Configuration
**Splunk Configurations to Check:**
- Configuration backup existence
- Version control for configurations
- Deployment server configurations

### CM-6: Configuration Settings
**Splunk Configurations to Check:**
- Security-relevant settings across all .conf files
- Disabled unnecessary features
- Secure defaults

### CM-7: Least Functionality
**Splunk Configurations to Check:**
- Disabled apps and add-ons
- Disabled scripted inputs
- Restricted search commands

## Identification and Authentication (IA)

### IA-2: Identification and Authentication
**Splunk Configurations to Check:**
- `authentication.conf`: Authentication methods
- LDAP/SAML/SSO configuration
- Multi-factor authentication settings

### IA-5: Authenticator Management
**Splunk Configurations to Check:**
- Password policy in `authentication.conf`
- Password complexity requirements
- Password history and reuse

### IA-8: Identification and Authentication (Non-Organizational Users)
**Splunk Configurations to Check:**
- External authentication configurations
- Certificate-based authentication

## System and Communications Protection (SC)

### SC-8: Transmission Confidentiality
**Splunk Configurations to Check:**
- `server.conf`: SSL/TLS settings
- `web.conf`: HTTPS enforcement
- `outputs.conf`: Encrypted forwarding

### SC-13: Cryptographic Protection
**Splunk Configurations to Check:**
- Certificate configuration
- Cipher suites
- TLS version requirements

### SC-28: Protection of Information at Rest
**Splunk Configurations to Check:**
- Index encryption settings
- KV store encryption
- Secret storage encryption

## System and Information Integrity (SI)

### SI-2: Flaw Remediation
**Splunk Configurations to Check:**
- Splunk version and patch level
- App and add-on versions
- Known vulnerability checks

### SI-4: Information System Monitoring
**Splunk Configurations to Check:**
- Real-time alerting configuration
- Correlation searches
- Notable event configuration

## Incident Response (IR)

### IR-6: Incident Reporting
**Splunk Configurations to Check:**
- Alert actions configuration
- Incident response app integration
- Automated notification settings

## Maintenance (MA)

### MA-4: Nonlocal Maintenance
**Splunk Configurations to Check:**
- Remote access configurations
- Deployment server security
- Management port restrictions

## FedRAMP-Specific Requirements

### Continuous Monitoring
- Splunk Enterprise Security configurations
- Real-time dashboards
- Automated compliance reporting

### Log Aggregation
- Centralized logging configuration
- Log source integration
- Data model compliance

### Vulnerability Scanning Integration
- Vulnerability scanner data inputs
- Asset inventory maintenance
- Risk scoring configurations

## Check Priority Levels

### Critical (Must Fix)
- Default credentials
- Unencrypted communications
- No authentication required
- Audit logging disabled

### High (Should Fix Soon)
- Weak password policies
- Missing MFA
- Excessive permissions
- Unpatched systems

### Medium (Plan to Fix)
- Suboptimal configurations
- Missing monitoring
- Incomplete logging

### Low (Consider Fixing)
- Best practice deviations
- Performance optimizations
- Enhanced monitoring