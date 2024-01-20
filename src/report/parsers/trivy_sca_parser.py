from ..data_schema.vulnerability import Vulnerability

CATEGORY = "Software Compose Analysis (SCA)"
TOOL_NAME = "Trivy"

DICT_WITHOUT_CVSS = {
    "nvd": {
        "V3Score": None
    }
}


def parse_trivy_sca_vulns(report: dict):
    """
    Parses the Trivy SCA vulnerabilities report and extracts the relevant information into a list of Vulnerability objects.

    Args:
        report (dict): The Trivy vulnerabilities report.

    Returns:
        list: A list of Vulnerability objects containing the extracted information.

    """
    vulnerabilities = []
    if report.get('Results', []):
        for source in report.get('Results', []):
            for vuln in source.get('Vulnerabilities', []):
                vulnerability = Vulnerability()
                vulnerability.set_name(vuln.get(
                    'VulnerabilityID') + " (" + vuln.get('PkgName') + "): " + vuln.get('Title'))
                vulnerability.set_description(vuln.get('Description'))
                vulnerability.set_identifier(vuln.get('VulnerabilityID'))
                vulnerability.set_severity(vuln.get('Severity'))
                vulnerability.set_cvss(
                    vuln.get('CVSS', DICT_WITHOUT_CVSS).get('nvd').get('V3Score'))
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
