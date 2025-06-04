# Splunk Security Compliance Checker

A comprehensive security compliance checking tool for Splunk installations that validates configurations against FedRAMP, NIST 800-53, and industry security best practices.

## Features

- **Comprehensive Security Checks**: Over 30 security configuration checks across multiple categories
- **Standards Compliance**: Validates against FedRAMP (Low, Moderate, High) and NIST 800-53 standards
- **Multiple Report Formats**: Generate reports in JSON, HTML, CSV, or console output
- **Severity-Based Findings**: Categorizes issues as Critical, High, Medium, or Low
- **Actionable Remediation**: Provides specific remediation steps for each failed check
- **Flexible Execution**: Run all checks or filter by specific control families

## Installation

1. Clone the repository:
```bash
git clone https://gitlab.com/hackIDLE/fedramp/fedramp-testing-public/siem/splunk-audit.git
cd splunk-audit
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python splunk_compliance.py --host splunk.example.com --port 8089 --username admin
```

### Scan Specific Control Families
```bash
python splunk_compliance.py --host splunk.example.com --username admin --controls AC,AU,SC
```

### Generate HTML Report
```bash
python splunk_compliance.py --host splunk.example.com --username admin \
    --report-format html --output compliance_report.html
```

### Check Against Specific Standard
```bash
python splunk_compliance.py --host splunk.example.com --username admin \
    --standard fedramp-high
```

### Skip SSL Verification (for testing only)
```bash
python splunk_compliance.py --host splunk.example.com --username admin \
    --skip-ssl-verify
```

## Compliance Check Categories

### 1. Authentication & Access Control (AC, IA)
- Default admin account security
- Service account management
- Account lockout policies
- Session timeout configuration
- Multi-factor authentication
- Password complexity requirements

### 2. Audit & Logging (AU)
- Audit logging enabled
- Audit content requirements
- Audit storage capacity
- Audit log protection
- Audit event generation

### 3. Encryption & Data Protection (SC)
- TLS/SSL configuration
- Web interface HTTPS
- Cipher suite strength
- Data-at-rest encryption

### 4. System Integrity (CM, SI)
- Configuration backups
- Secure configuration settings
- Unnecessary features disabled
- Splunk version compliance
- Security patch status

## Report Formats

### Console Output (Default)
Displays a summary and detailed findings grouped by severity in the terminal.

### JSON Report
Structured JSON output with metadata, summary statistics, and detailed results.

### HTML Report
Professional HTML report with color-coded severity levels and summary dashboard.

### CSV Report
Spreadsheet-compatible format for further analysis and tracking.

## Compliance Standards

### FedRAMP Low
Basic security controls suitable for low-impact systems.

### FedRAMP Moderate
Enhanced security controls for moderate-impact systems (default).

### FedRAMP High
Stringent security controls for high-impact systems.

### NIST 800-53
Comprehensive security control catalog without FedRAMP tailoring.

## Configuration Files

### checks.yaml
Defines all compliance checks with their properties:
- NIST control mapping
- Severity levels
- Check logic
- Expected values

### severity_mapping.yaml
Configures severity levels and scoring:
- Severity scores
- SLA requirements
- Pass/fail thresholds

## Exit Codes

- `0`: All checks passed or score above threshold
- `1`: Critical findings or score below threshold

## Security Considerations

- Credentials are never stored or logged
- Read-only operations only
- Supports token-based authentication
- SSL/TLS verification by default

## Extending the Tool

To add new compliance checks:

1. Add check definition to `config/checks.yaml`
2. Implement check logic in appropriate module
3. Update documentation

## Troubleshooting

### Connection Issues
- Verify Splunk management port (default 8089)
- Check firewall rules
- Ensure user has appropriate permissions

### Permission Errors
- User needs admin or admin-equivalent role
- Some checks require specific capabilities

### SSL Certificate Errors
- Use `--skip-ssl-verify` for self-signed certificates (testing only)
- Import CA certificates for production use

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a merge request

## Support

For issues and questions:
- Create an issue in GitLab
- Contact the security team