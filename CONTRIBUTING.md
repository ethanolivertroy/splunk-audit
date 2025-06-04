# Contributing to Splunk Security Compliance Checker

We welcome contributions to improve the Splunk Security Compliance Checker! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Issues

1. Check if the issue already exists in the GitLab issues
2. Create a new issue with:
   - Clear title describing the problem
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Splunk version and environment details

### Suggesting Enhancements

1. Check existing issues for similar suggestions
2. Create an issue with the "enhancement" label
3. Describe the enhancement and its benefits
4. Provide examples if applicable

### Code Contributions

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes following the code style guidelines
4. Add or update tests as needed
5. Update documentation
6. Submit a merge request

## Development Setup

```bash
# Clone your fork
git clone https://gitlab.com/YOUR_USERNAME/splunk-audit.git
cd splunk-audit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python test_installation.py
```

## Code Style Guidelines

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and small
- Use type hints where appropriate

## Adding New Compliance Checks

1. Add check definition to `config/checks.yaml`:
```yaml
NEW-CHECK-ID:
  name: "Descriptive Check Name"
  description: "What this check validates"
  nist_control: "XX-#"
  fedramp_baseline: ["low", "moderate", "high"]
  severity: "critical|high|medium|low"
  check_type: "api|config|..."
  # Additional check-specific configuration
```

2. Implement check logic in the appropriate module:
   - Authentication checks → `modules/auth_checks.py`
   - Audit checks → `modules/audit_checks.py`
   - Encryption checks → `modules/encryption_checks.py`
   - System checks → `modules/system_checks.py`

3. Follow the existing pattern:
```python
def _check_new_feature(self, config: Dict[str, Any]) -> Dict[str, Any]:
    """Check description"""
    # Implementation
    return {
        'status': 'PASS|FAIL|WARN',
        'details': 'Specific details about the result',
        'remediation': 'How to fix if failed'
    }
```

4. Update documentation

## Testing

- Test your changes against multiple Splunk versions if possible
- Ensure no false positives
- Verify remediation steps are accurate
- Test all report formats

## Documentation

- Update README.md for new features
- Add examples to example_usage.md
- Update inline code documentation
- Document any new configuration options

## Commit Messages

Use clear, descriptive commit messages:
- `Add: New feature or check`
- `Fix: Bug fix`
- `Update: Enhancement or improvement`
- `Docs: Documentation changes`
- `Test: Test additions or changes`

## Review Process

1. All merge requests require review
2. Ensure CI/CD checks pass
3. Address reviewer feedback
4. Maintain backward compatibility

## Security Considerations

- Never commit credentials or sensitive data
- Ensure all checks are read-only
- Validate all inputs
- Follow secure coding practices

## Questions?

Create an issue with the "question" label or contact the maintainers.

Thank you for contributing to improve Splunk security compliance!