from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Secrets detection"
TOOL_NAME = "GitLeaks"

def parse_gitleaks_vulns(report: dict):
    vulnerabilities = []
    for result in report:
        name = 'Secret detected in ' + result.get('File')
        vulnerabilities.append(Vulnerability(name, result.get('Description'),"CWE-798","High", "N/A", "N/A",
                                      CATEGORY, result.get('RuleID'), result.get('File'),
                                      result.get('EndLine'),"Remove and rotate the hardcoded secret",
                                      "https://cwe.mitre.org/data/definitions/798.html",[TOOL_NAME]))
    return vulnerabilities