# Example Usage Guide

## Prerequisites

1. Splunk instance with management port accessible (default: 8089)
2. Admin or admin-equivalent credentials
3. Python 3.8+ installed
4. Dependencies installed via `pip install -r requirements.txt`

## Quick Start Examples

### 1. Basic Compliance Check
```bash
python splunk_compliance.py --host localhost --port 8089 --username admin
```
You'll be prompted for the password.

### 2. Check Specific Control Families
```bash
# Check only Authentication and Audit controls
python splunk_compliance.py --host splunk.company.com --username admin --controls AC,AU
```

### 3. Generate Different Report Formats

#### HTML Report (Best for sharing)
```bash
python splunk_compliance.py --host splunk.company.com --username admin \
    --report-format html --output compliance_report.html
```

#### JSON Report (Best for automation)
```bash
python splunk_compliance.py --host splunk.company.com --username admin \
    --report-format json --output compliance_data.json
```

#### CSV Report (Best for tracking)
```bash
python splunk_compliance.py --host splunk.company.com --username admin \
    --report-format csv --output compliance_results.csv
```

### 4. Different Compliance Standards

#### FedRAMP High
```bash
python splunk_compliance.py --host splunk.company.com --username admin \
    --standard fedramp-high
```

#### NIST 800-53 (All Controls)
```bash
python splunk_compliance.py --host splunk.company.com --username admin \
    --standard nist-800-53
```

### 5. Development/Testing Environment
```bash
# Skip SSL verification for self-signed certificates
python splunk_compliance.py --host dev-splunk.local --username admin \
    --skip-ssl-verify --verbose
```

## Understanding the Output

### Console Output Example
```
==============================================================
Splunk Security Compliance Checker
Standard: FEDRAMP-MODERATE
Host: splunk.company.com:8089
==============================================================

Connecting to Splunk...
Successfully connected to Splunk

Running compliance checks [####################################] 100%

==============================================================
COMPLIANCE CHECK SUMMARY
==============================================================
Total Checks: 25
Passed: 18
Failed: 7
Compliance Score: 72.5%

CRITICAL FINDINGS:
  - SC-8-1: TLS Configuration
  - AU-2-1: Audit Logging Enabled

HIGH SEVERITY FAILURES:

  ▸ AC-7-1: Account Lockout Policy
    Control: AC-7
    Details: Account lockout is not configured
    Remediation: Configure lockoutAttempts=3 and lockoutDuration=900 in authentication.conf
```

### Report Contents

#### Summary Section
- Overall compliance score
- Pass/fail counts by severity
- Executive summary

#### Detailed Findings
- Check ID and name
- NIST control mapping
- Current configuration status
- Specific remediation steps

#### Severity Levels
- **Critical**: Immediate action required (e.g., default passwords, no encryption)
- **High**: Address within 7 days (e.g., weak passwords, missing MFA)
- **Medium**: Plan remediation within 30 days (e.g., suboptimal settings)
- **Low**: Best practice recommendations

## Common Scenarios

### Pre-Audit Preparation
```bash
# Run full compliance check and generate HTML report
python splunk_compliance.py --host prod-splunk.company.com --username admin \
    --standard fedramp-moderate --report-format html \
    --output pre_audit_report_$(date +%Y%m%d).html
```

### Continuous Monitoring
```bash
# Run daily checks for critical controls only
python splunk_compliance.py --host prod-splunk.company.com --username admin \
    --controls AC,AU,SC --report-format json --output daily_check.json

# Check exit code for automation
if [ $? -eq 0 ]; then
    echo "Compliance check passed"
else
    echo "Compliance issues detected"
    # Send alert, create ticket, etc.
fi
```

### Post-Remediation Verification
```bash
# Re-run specific checks after fixing issues
python splunk_compliance.py --host prod-splunk.company.com --username admin \
    --controls SC --verbose
```

## Troubleshooting

### Connection Refused
```
Error: Connection refused to splunk.company.com:8089
```
- Verify Splunk is running
- Check management port (default 8089)
- Ensure firewall allows connection

### Authentication Failed
```
Error: Login failed
```
- Verify username and password
- Check if account is locked
- Ensure user has admin role

### SSL Certificate Error
```
Error: SSL: CERTIFICATE_VERIFY_FAILED
```
- For production: Install proper certificates
- For testing: Use --skip-ssl-verify flag

### Permission Denied
```
Error: Insufficient permissions to access configuration
```
- User needs admin or admin-equivalent role
- Some checks require specific capabilities