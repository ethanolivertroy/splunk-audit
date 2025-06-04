# Changelog

All notable changes to the Splunk Security Compliance Checker will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-XX

### Added
- Initial release of Splunk Security Compliance Checker
- Support for FedRAMP Low, Moderate, and High standards
- Support for NIST 800-53 compliance checks
- 30+ security configuration checks across 4 categories:
  - Authentication & Access Control (AC, IA)
  - Audit & Logging (AU)
  - Encryption & Data Protection (SC)
  - System Integrity (CM, SI)
- Multiple report formats: Console, JSON, HTML, CSV
- Severity-based findings (Critical, High, Medium, Low)
- Actionable remediation guidance for each check
- Command-line interface with flexible options
- SSL/TLS verification with skip option for testing
- Filtering by specific control families
- Comprehensive documentation and examples

### Security
- Read-only operations ensure no system modifications
- Secure credential handling
- SSL/TLS verification by default

### Documentation
- Comprehensive README with installation and usage instructions
- Example usage guide with common scenarios
- NIST to Splunk configuration mapping
- Contributing guidelines
- MIT License