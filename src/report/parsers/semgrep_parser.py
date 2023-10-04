from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Static Application Security Testing (SAST)"
TOOL_NAME = "Semgrep"

def parse_semgrep_vulns(report: dict):
    vulnerabilities = []
    for result in report.get('results'):
        name = result.get('check_id') + 'detected in your code'
        vulnerabilities.append(Vulnerability(name, result.get('extra').get('message'),"N/A",result.get('extra').get('severity'),"N/A","N/A",
                                      CATEGORY, result.get('check_id'), result.get('path'),
                                      result.get('metavars').get('end').get('line'),"Not defined by the tool","Not defined by the tool",TOOL_NAME))
    return vulnerabilities