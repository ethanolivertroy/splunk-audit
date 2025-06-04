"""Report generation for compliance check results"""

import json
import csv
from datetime import datetime
from typing import Dict, List, Any
from io import StringIO
import click
from tabulate import tabulate
from jinja2 import Template


class ReportGenerator:
    """Generates compliance reports in various formats"""
    
    def __init__(self, severity_config: Dict[str, Any]):
        self.severity_config = severity_config
    
    def calculate_compliance_score(self, results: List[Dict[str, Any]]) -> float:
        """Calculate overall compliance score"""
        if not results:
            return 0.0
        
        total_weight = 0
        passed_weight = 0
        
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        
        for result in results:
            severity = result.get('severity', 'medium')
            weight = severity_weights.get(severity, 1)
            total_weight += weight
            
            if result.get('status') == 'PASS':
                passed_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return (passed_weight / total_weight) * 100
    
    def generate_report(self, results: List[Dict[str, Any]], format: str = 'json', 
                       metadata: Dict[str, Any] = None) -> str:
        """Generate report in specified format"""
        if format == 'json':
            return self._generate_json_report(results, metadata)
        elif format == 'html':
            return self._generate_html_report(results, metadata)
        elif format == 'csv':
            return self._generate_csv_report(results, metadata)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def display_console_report(self, results: List[Dict[str, Any]]):
        """Display formatted report in console"""
        # Group results by severity
        by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for result in results:
            severity = result.get('severity', 'medium')
            if severity in by_severity:
                by_severity[severity].append(result)
        
        # Display failures by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            failures = [r for r in by_severity[severity] if r['status'] == 'FAIL']
            
            if failures:
                color = self.severity_config['severity_levels'][severity]['color']
                click.echo(f"\n{click.style(f'{severity.upper()} SEVERITY FAILURES:', fg=color, bold=True)}")
                
                for failure in failures:
                    click.echo(f"\n  {click.style('▸', fg=color)} {failure['check_id']}: {failure['name']}")
                    click.echo(f"    Control: {failure['nist_control']}")
                    click.echo(f"    Details: {failure['details']}")
                    if failure.get('remediation'):
                        click.echo(f"    {click.style('Remediation:', fg='green')} {failure['remediation']}")
    
    def _generate_json_report(self, results: List[Dict[str, Any]], 
                             metadata: Dict[str, Any] = None) -> str:
        """Generate JSON format report"""
        report = {
            'metadata': metadata or {},
            'summary': self._generate_summary(results),
            'results': results
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _generate_html_report(self, results: List[Dict[str, Any]], 
                             metadata: Dict[str, Any] = None) -> str:
        """Generate HTML format report"""
        template = Template('''
<!DOCTYPE html>
<html>
<head>
    <title>Splunk Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .results { margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warn { color: orange; font-weight: bold; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ffe6cc; }
        .medium { background-color: #ffffcc; }
        .low { background-color: #e6f3ff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Splunk Security Compliance Report</h1>
        <p>Host: {{ metadata.host }}</p>
        <p>Standard: {{ metadata.standard }}</p>
        <p>Scan Date: {{ metadata.scan_date }}</p>
        <p>Overall Score: <strong>{{ "%.1f"|format(metadata.score) }}%</strong></p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Checks: {{ summary.total }}</p>
        <p>Passed: <span class="pass">{{ summary.passed }}</span></p>
        <p>Failed: <span class="fail">{{ summary.failed }}</span></p>
        <p>Warnings: <span class="warn">{{ summary.warnings }}</span></p>
    </div>
    
    <div class="results">
        <h2>Detailed Results</h2>
        <table>
            <tr>
                <th>Check ID</th>
                <th>Name</th>
                <th>NIST Control</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Details</th>
                <th>Remediation</th>
            </tr>
            {% for result in results %}
            <tr class="{{ result.severity }}">
                <td>{{ result.check_id }}</td>
                <td>{{ result.name }}</td>
                <td>{{ result.nist_control }}</td>
                <td>{{ result.severity|upper }}</td>
                <td class="{{ result.status|lower }}">{{ result.status }}</td>
                <td>{{ result.details }}</td>
                <td>{{ result.remediation }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
        ''')
        
        summary = self._generate_summary(results)
        
        return template.render(
            metadata=metadata or {},
            summary=summary,
            results=results
        )
    
    def _generate_csv_report(self, results: List[Dict[str, Any]], 
                            metadata: Dict[str, Any] = None) -> str:
        """Generate CSV format report"""
        output = StringIO()
        
        # Write metadata as comments
        if metadata:
            output.write(f"# Splunk Compliance Report\n")
            output.write(f"# Host: {metadata.get('host', 'Unknown')}\n")
            output.write(f"# Standard: {metadata.get('standard', 'Unknown')}\n")
            output.write(f"# Scan Date: {metadata.get('scan_date', 'Unknown')}\n")
            output.write(f"# Score: {metadata.get('score', 0):.1f}%\n")
            output.write("\n")
        
        # Write CSV data
        fieldnames = ['check_id', 'name', 'nist_control', 'severity', 
                     'status', 'details', 'remediation']
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            writer.writerow({
                'check_id': result.get('check_id', ''),
                'name': result.get('name', ''),
                'nist_control': result.get('nist_control', ''),
                'severity': result.get('severity', ''),
                'status': result.get('status', ''),
                'details': result.get('details', ''),
                'remediation': result.get('remediation', '')
            })
        
        return output.getvalue()
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics"""
        summary = {
            'total': len(results),
            'passed': sum(1 for r in results if r['status'] == 'PASS'),
            'failed': sum(1 for r in results if r['status'] == 'FAIL'),
            'warnings': sum(1 for r in results if r['status'] == 'WARN'),
            'errors': sum(1 for r in results if r['status'] == 'ERROR'),
            'skipped': sum(1 for r in results if r['status'] == 'SKIP'),
            'by_severity': {
                'critical': {
                    'total': sum(1 for r in results if r['severity'] == 'critical'),
                    'failed': sum(1 for r in results if r['severity'] == 'critical' and r['status'] == 'FAIL')
                },
                'high': {
                    'total': sum(1 for r in results if r['severity'] == 'high'),
                    'failed': sum(1 for r in results if r['severity'] == 'high' and r['status'] == 'FAIL')
                },
                'medium': {
                    'total': sum(1 for r in results if r['severity'] == 'medium'),
                    'failed': sum(1 for r in results if r['severity'] == 'medium' and r['status'] == 'FAIL')
                },
                'low': {
                    'total': sum(1 for r in results if r['severity'] == 'low'),
                    'failed': sum(1 for r in results if r['severity'] == 'low' and r['status'] == 'FAIL')
                }
            }
        }
        
        return summary
    
    def generate_executive_summary(self, results: List[Dict[str, Any]], 
                                 metadata: Dict[str, Any] = None) -> str:
        """Generate executive summary"""
        score = self.calculate_compliance_score(results)
        summary = self._generate_summary(results)
        
        critical_findings = [r for r in results if r['severity'] == 'critical' and r['status'] == 'FAIL']
        high_findings = [r for r in results if r['severity'] == 'high' and r['status'] == 'FAIL']
        
        exec_summary = f"""
EXECUTIVE SUMMARY
================

Organization: {metadata.get('organization', 'Unknown')}
Scan Date: {metadata.get('scan_date', datetime.now().isoformat())}
Compliance Standard: {metadata.get('standard', 'FedRAMP Moderate')}

OVERALL COMPLIANCE SCORE: {score:.1f}%

KEY FINDINGS:
- Total Security Checks: {summary['total']}
- Passed: {summary['passed']}
- Failed: {summary['failed']}
- Critical Issues: {len(critical_findings)}
- High Priority Issues: {len(high_findings)}

RISK ASSESSMENT:
"""
        
        if critical_findings:
            exec_summary += f"- CRITICAL: Immediate action required for {len(critical_findings)} critical findings\n"
        
        if score < 70:
            exec_summary += "- HIGH RISK: Overall compliance score is below acceptable threshold\n"
        elif score < 85:
            exec_summary += "- MEDIUM RISK: Several compliance gaps need to be addressed\n"
        else:
            exec_summary += "- LOW RISK: System is largely compliant with minor issues\n"
        
        exec_summary += "\nRECOMMENDED ACTIONS:\n"
        
        if critical_findings:
            exec_summary += "1. Address all critical findings within 24-48 hours\n"
        
        if high_findings:
            exec_summary += "2. Remediate high priority issues within 7 days\n"
        
        exec_summary += "3. Implement continuous compliance monitoring\n"
        exec_summary += "4. Schedule regular compliance assessments\n"
        
        return exec_summary