from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Static Application Security Testing (SAST)"
TOOL_NAME = "Semgrep"

def parse_semgrep_vulns(report: dict):
    vulnerabilities = []
    for result in report.get('results',[]):
        try:
            vulnerability = Vulnerability()
            vulnerability.set_name(result.get('extra').get('metadata').get('vulnerability_class')[0] + ' detected in your code')
            vulnerability.set_location("")
            if result.get('end') and result.get('start').get('line'):
                vulnerability.set_location(result.get('start').get('line'))
            elif result.get('end') and result.get('end').get('line'):
                vulnerability.set_location(result.get('end').get('line'))
            else:
                vulnerability.set_location("Not detected")
            vulnerability.set_description(result.get('extra').get('message'))
            vulnerability.set_identifier(result.get('extra').get('metadata').get('cwe')[0])
            vulnerability.set_severity(result.get('extra').get('metadata').get('impact'))
            vulnerability.set_cvss(None)
            vulnerability.set_epss(None)
            vulnerability.set_category(CATEGORY)
            vulnerability.set_rule(result.get('check_id'))
            vulnerability.set_file(result.get('path'))
            vulnerability.set_fix("Not defined by the tool")
            vulnerability.set_references([result.get('extra').get('metadata').get('references')[0]])
            vulnerability.set_tools([TOOL_NAME])

            vulnerabilities.append(vulnerability)
        except Exception as e:
            print(f"Error parsing vulnerability: {e}")

    return vulnerabilities