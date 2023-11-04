from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Static Application Security Testing (SAST)"
TOOL_NAME = "Semgrep"

def parse_semgrep_vulns(report: dict):
    vulnerabilities = []
    for result in report.get('results'):
        name = result.get('extra').get('metadata').get('vulnerability_class')[0] + ' detected in your code'
        location = ""
        if result.get('end') and result.get('start').get('line'):
            location = result.get('start').get('line')
        elif result.get('end') and result.get('end').get('line'):
            location = result.get('end').get('line')
        else:
            location = "Not detected"
        vulnerabilities.append(Vulnerability(name, result.get('extra').get('message'),result.get('extra').get('metadata').get('cwe')[0],result.get('extra').get('metadata').get('impact'),"N/A","N/A",
                                      CATEGORY, result.get('check_id'), result.get('path'),
                                      location,"Not defined by the tool",result.get('extra').get('metadata').get('references')[0],[TOOL_NAME]))
    return vulnerabilities