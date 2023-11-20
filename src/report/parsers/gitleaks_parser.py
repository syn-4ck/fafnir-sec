from typing import Dict, List

from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Secrets detection"
TOOL_NAME = "GitLeaks"

def parse_gitleaks_vulns(report: List[Dict[str, str]]) -> List[Vulnerability]:
    """
    Parses the gitleaks vulnerabilities report and creates a list of Vulnerability objects.
    
    Args:
        report (List[Dict[str, str]]): The gitleaks vulnerabilities report as a list of dictionaries.
        
    Returns:
        List[Vulnerability]: A list of Vulnerability objects representing the parsed vulnerabilities.
    """
    vulnerabilities: List[Vulnerability] = []
    for result in report:
        try:
            name = 'Secret detected in ' + result.get('File')
            vulnerability = Vulnerability()
            vulnerability.set_name(name)
            vulnerability.set_description(result.get('Description'))
            vulnerability.set_identifier("CWE-798")
            vulnerability.set_severity("High")
            vulnerability.set_cvss(None)
            vulnerability.set_epss(None)
            vulnerability.set_category(CATEGORY)
            vulnerability.set_rule(result.get('RuleID'))
            vulnerability.set_file(result.get('File'))
            vulnerability.set_location(result.get('EndLine'))
            vulnerability.set_fix("Remove and rotate the hardcoded secret")
            vulnerability.set_link("https://cwe.mitre.org/data/definitions/798.html")
            vulnerability.set_tools([TOOL_NAME])
            vulnerabilities.append(vulnerability)
        except Exception as e:
            print(f"Error parsing vulnerability: {e}")
    return vulnerabilities
