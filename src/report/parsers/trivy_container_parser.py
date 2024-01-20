from typing import List, Dict

from ..data_schema.vulnerability import Vulnerability

CATEGORY = "Container analysis"
TOOL_NAME = "Trivy"

NOT_EXISTING_DICT_CVSS = {
    "CVSS": {
        "ANY_KEY": {
            "V3Score": None
        }
    }
}


def parse_trivy_container_vulns(report: Dict[str, List[Dict[str, str]]]) -> List[Vulnerability]:
    """
    Parses the Trivy container vulnerabilities report and returns a list of Vulnerability objects.

    Args:
        report (Dict[str, List[Dict[str, str]]]): The Trivy container vulnerabilities report.

    Returns:
        List[Vulnerability]: A list of Vulnerability objects representing the vulnerabilities found in the report.
    """
    vulnerabilities: List[Vulnerability] = []
    for source in report.get('Results', []):
        for vuln in source.get('Vulnerabilities', []):
            vulnerability = Vulnerability()
            vulnerability.set_name(vuln.get(
                'VulnerabilityID') + " (" + vuln.get('PkgName') + "): " + vuln.get('Title'))
            vulnerability.set_description(vuln.get('Description'))
            vulnerability.set_identifier(vuln.get('VulnerabilityID'))
            vulnerability.set_severity(vuln.get('Severity'))
            vulnerability.set_cvss((vuln.get('CVSS').get(list(vuln.get('CVSS').keys())[0]) if len(
                list(vuln.get('CVSS', {}).keys())) > 0 else {}).get('V3Score', None))
            vulnerability.set_epss(None)
            vulnerability.set_category(CATEGORY)
            vulnerability.set_rule(vuln.get('VulnerabilityID'))
            vulnerability.set_file(source.get('Target'))
            vulnerability.set_location(1)
            vulnerability.set_fix(vuln.get('FixedVersion'))
            vulnerability.set_link(vuln.get('PrimaryURL'))
            vulnerability.set_tools([TOOL_NAME])
            vulnerabilities.append(vulnerability)
    return vulnerabilities
