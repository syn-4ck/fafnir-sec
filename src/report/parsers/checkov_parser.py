from report.data_schema.vulnerability import Vulnerability

CATEGORY = "IaC code analysis"
TOOL_NAME = "Checkov"

def parse_checkov_vulns(report: dict):
    vulnerabilities = []
    for vuln in report.get('results').get('failed_checks'):
            vulnerabilities.append(Vulnerability(vuln.get('check_name'), vuln.get('check_id') + ": " + vuln.get('check_name'),vuln.get('check_id'),vuln.get('severity'),'N/A', "N/A",
                                      CATEGORY, vuln.get('check_id'), vuln.get('file_path'),
                                      vuln.get('resource'),vuln.get('check_name'),vuln.get('guideline'),TOOL_NAME))
    return vulnerabilities