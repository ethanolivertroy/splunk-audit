# Security Policy

## Supported Versions

Currently supported versions for security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

1. **DO NOT** create a public issue
2. Send details to the security team through GitLab's confidential issue feature
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Considerations

This tool is designed with security in mind:

- **Read-only operations**: The tool only reads configurations and never modifies Splunk settings
- **Credential handling**: Passwords are never stored or logged
- **SSL/TLS verification**: Enabled by default, only disable for testing
- **Input validation**: All inputs are validated before use

## Best Practices

When using this tool:

1. Run from a secure, trusted environment
2. Use service accounts with minimal required permissions
3. Store reports securely (they may contain sensitive configuration details)
4. Regularly update to the latest version
5. Review all findings before implementing remediation

## Disclosure Policy

- We will acknowledge receipt within 48 hours
- We will provide regular updates on the progress
- We will notify you when the vulnerability is fixed
- We appreciate responsible disclosure

Thank you for helping keep this project secure!