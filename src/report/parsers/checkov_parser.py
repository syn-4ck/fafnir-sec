from report.data_schema.vulnerability import Vulnerability

TOOL_NAME = "Checkov"

def _get_category(category):
     if category == "terraform":
          return "IaC code analysis"
     elif category == "dockerfile":
          return "Container analysis"
     elif category == "secrets":
          return "Secrets detection"
     else:
          return ""

def parse_checkov_vulns(report: dict):
    vulnerabilities = []
    for check_type in report:
        for vuln in check_type.get('results').get('failed_checks'):
                vulnerabilities.append(Vulnerability(vuln.get('check_name'), vuln.get('check_id') + ": " + vuln.get('check_name'),vuln.get('check_id'),vuln.get('severity'),'N/A', "N/A",
                                        _get_category(check_type.get('check_type')), vuln.get('check_id'), vuln.get('file_path'),
                                        vuln.get('resource'),vuln.get('check_name'),vuln.get('guideline'),[TOOL_NAME]))
    return vulnerabilities