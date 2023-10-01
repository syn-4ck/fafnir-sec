from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Static Application Security Testing (SAST)"
TOOL_NAME = "Bandit"

def parse_bandit_vulns(report: dict):
    vulnerabilities = []
    for result in report.get('results'):
        vulnerabilities.append(Vulnerability(result.get('issue_text'), result.get('issue_text') + ": " + result.get('filename'),"",result.get('issue_severity'), "N/A", "N/A",
                                      CATEGORY, result.get('test_id'), result.get('filename'),
                                      result.get('line_number'), "", result.get('more_info'),TOOL_NAME))
    return vulnerabilities