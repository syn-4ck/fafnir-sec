from typing import List, Dict

from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Static Application Security Testing (SAST)"
TOOL_NAME = "Bandit"

def parse_bandit_vulns(report: Dict[str, List[Dict[str, str]]]) -> List[Vulnerability]:
    """
    Parse the bandit vulnerabilities from the given report.

    Args:
        report (dict): The report containing the vulnerabilities.

    Returns:
        List[Vulnerability]: A list of Vulnerability objects representing the parsed vulnerabilities.
    """
    vulnerabilities: List[Vulnerability] = []
    for result in report.get('results',[]):
        try:
            vulnerability = Vulnerability()
            vulnerability.set_name(result.get('issue_text'))
            vulnerability.set_description(result.get('issue_text') + ": " + result.get('filename'))
            vulnerability.set_severity(result.get('issue_severity'))
            vulnerability.set_identifier('')
            vulnerability.set_cvss(None)
            vulnerability.set_epss(None)
            vulnerability.set_category(CATEGORY)
            vulnerability.set_rule(result.get('test_id'))
            vulnerability.set_file(result.get('filename'))
            vulnerability.set_location(result.get('line_number'))
            vulnerability.set_fix("Not defined by the tool")
            vulnerability.set_link(result.get('more_info'))
            vulnerability.set_tools([TOOL_NAME])
            vulnerabilities.append(vulnerability)
        except Exception as e:
            print(f"Error parsing vulnerability: {e}")

    return vulnerabilities
