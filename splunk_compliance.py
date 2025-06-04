#!/usr/bin/env python3
"""
Splunk Security Compliance Checker
Validates Splunk installations against FedRAMP and NIST 800-53 standards

Copyright (c) 2024 HackIDLE FedRAMP Testing Team
Licensed under the MIT License (see LICENSE file)

Version: 1.0.0
"""

import click
import sys
import os
import json
from datetime import datetime
from pathlib import Path

from modules.api_client import SplunkAPIClient
from modules.auth_checks import AuthenticationChecker
from modules.audit_checks import AuditChecker
from modules.encryption_checks import EncryptionChecker
from modules.system_checks import SystemChecker
from reports.report_generator import ReportGenerator
from utils.config_parser import ConfigParser


@click.command()
@click.option('--host', required=True, help='Splunk host address')
@click.option('--port', default=8089, help='Splunk management port (default: 8089)')
@click.option('--username', required=True, help='Splunk username')
@click.option('--password', prompt=True, hide_input=True, help='Splunk password')
@click.option('--controls', help='Comma-separated list of control families to check (e.g., AC,AU,SC)')
@click.option('--standard', type=click.Choice(['fedramp-low', 'fedramp-moderate', 'fedramp-high', 'nist-800-53']), 
              default='fedramp-moderate', help='Compliance standard to check against')
@click.option('--report-format', type=click.Choice(['json', 'html', 'csv', 'console']), 
              default='console', help='Output format for the report')
@click.option('--output', type=click.Path(), help='Output file path (default: stdout)')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
@click.option('--skip-ssl-verify', is_flag=True, help='Skip SSL certificate verification')
def main(host, port, username, password, controls, standard, report_format, output, verbose, skip_ssl_verify):
    """Splunk Security Compliance Checker - Validate your Splunk installation"""
    
    click.echo(f"{'='*60}")
    click.echo("Splunk Security Compliance Checker")
    click.echo(f"Standard: {standard.upper()}")
    click.echo(f"Host: {host}:{port}")
    click.echo(f"{'='*60}\n")
    
    # Initialize configuration parser
    config_parser = ConfigParser()
    compliance_checks = config_parser.load_compliance_checks()
    severity_config = config_parser.load_severity_config()
    
    # Filter checks by control families if specified
    if controls:
        control_list = [c.strip().upper() for c in controls.split(',')]
        compliance_checks = config_parser.filter_checks_by_controls(compliance_checks, control_list)
    
    # Filter checks by standard
    compliance_checks = config_parser.filter_checks_by_standard(compliance_checks, standard)
    
    # Initialize Splunk API client
    try:
        click.echo("Connecting to Splunk...")
        api_client = SplunkAPIClient(
            host=host,
            port=port,
            username=username,
            password=password,
            verify_ssl=not skip_ssl_verify
        )
        
        if not api_client.test_connection():
            click.echo(click.style("Failed to connect to Splunk!", fg='red'))
            sys.exit(1)
            
        click.echo(click.style("Successfully connected to Splunk\n", fg='green'))
        
    except Exception as e:
        click.echo(click.style(f"Connection error: {str(e)}", fg='red'))
        sys.exit(1)
    
    # Initialize checkers
    checkers = {
        'authentication': AuthenticationChecker(api_client, compliance_checks.get('authentication', {})),
        'audit_logging': AuditChecker(api_client, compliance_checks.get('audit_logging', {})),
        'encryption': EncryptionChecker(api_client, compliance_checks.get('encryption', {})),
        'system_integrity': SystemChecker(api_client, compliance_checks.get('system_integrity', {}))
    }
    
    # Run compliance checks
    all_results = []
    total_checks = sum(len(checks) for checks in compliance_checks.values())
    current_check = 0
    
    with click.progressbar(length=total_checks, label='Running compliance checks') as bar:
        for category, checker in checkers.items():
            if category in compliance_checks:
                if verbose:
                    click.echo(f"\nChecking {category.replace('_', ' ').title()}...")
                    
                category_results = checker.run_checks(verbose=verbose)
                all_results.extend(category_results)
                
                bar.update(len(compliance_checks[category]))
                current_check += len(compliance_checks[category])
    
    click.echo("\n")
    
    # Generate report
    report_generator = ReportGenerator(severity_config)
    
    # Calculate compliance score
    score = report_generator.calculate_compliance_score(all_results)
    
    # Display summary
    click.echo(f"{'='*60}")
    click.echo("COMPLIANCE CHECK SUMMARY")
    click.echo(f"{'='*60}")
    click.echo(f"Total Checks: {len(all_results)}")
    
    passed = sum(1 for r in all_results if r['status'] == 'PASS')
    failed = sum(1 for r in all_results if r['status'] == 'FAIL')
    
    click.echo(f"Passed: {click.style(str(passed), fg='green')}")
    click.echo(f"Failed: {click.style(str(failed), fg='red')}")
    click.echo(f"Compliance Score: {click.style(f'{score:.1f}%', fg='yellow' if score >= 80 else 'red')}")
    
    # Show critical findings
    critical_findings = [r for r in all_results if r['status'] == 'FAIL' and r['severity'] == 'critical']
    if critical_findings:
        click.echo(f"\n{click.style('CRITICAL FINDINGS:', fg='red', bold=True)}")
        for finding in critical_findings:
            click.echo(f"  - {finding['check_id']}: {finding['name']}")
    
    # Generate full report
    if report_format == 'console':
        report_generator.display_console_report(all_results)
    else:
        report_content = report_generator.generate_report(
            all_results, 
            format=report_format,
            metadata={
                'host': host,
                'standard': standard,
                'scan_date': datetime.now().isoformat(),
                'score': score
            }
        )
        
        if output:
            with open(output, 'w') as f:
                f.write(report_content)
            click.echo(f"\nReport saved to: {output}")
        else:
            click.echo(f"\n{report_content}")
    
    # Exit with appropriate code
    if score < severity_config['scoring']['pass_threshold'] or critical_findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()