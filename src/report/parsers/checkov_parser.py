from ..data_schema.vulnerability import Vulnerability
from typing import Dict, List

TOOL_NAME = "Checkov"


def _get_category(category):
    """
    Retrieves the category description based on the given category.

    Parameters:
        category (str): The category for which the description is to be retrieved.

    Returns:
        str: The description of the category. If the category is not found, an empty string is returned.
    """
    categories = {
        "terraform": "IaC code analysis",
        "dockerfile": "Container analysis",
        "secrets": "Secrets detection",
    }
    return categories.get(category, "")


def parse_checkov_vulns(report: Dict[str, Dict[str, Dict[str, List[Dict[str, str]]]]]) -> List[Vulnerability]:
    """
    Parses the Checkov vulnerabilities report and returns a list of Vulnerability objects.

    Parameters:
        report (Dict[str, Dict[str, Dict[str, List[Dict[str, str]]]]]): The Checkov vulnerabilities report as a dictionary.

    Returns:
        List[Vulnerability]: A list of Vulnerability objects representing the parsed vulnerabilities.
    """
    vulnerabilities: List[Vulnerability] = []
    for r in report:
        if r.get('results'):
            for vuln in r.get('results').get('failed_checks'):
                try:
                    vulnerability = Vulnerability()
                    vulnerability.set_name(vuln['check_name'])
                    vulnerability.set_description(
                        f"{vuln['check_id']}: {vuln['check_name']}")
                    vulnerability.set_identifier(vuln['check_id'])
                    vulnerability.set_severity(vuln['severity'])
                    vulnerability.set_cvss(None)
                    vulnerability.set_epss(None)
                    vulnerability.set_category(
                        _get_category(r.get("check_type")))
                    vulnerability.set_rule(vuln['check_id'])
                    vulnerability.set_file(vuln['file_path'])
                    vulnerability.set_location(vuln['resource'])
                    vulnerability.set_fix(vuln['check_name'])
                    vulnerability.set_link(vuln['guideline'])
                    vulnerability.set_tools([TOOL_NAME])
                    vulnerabilities.append(vulnerability)
                except KeyError:
                    continue
    return vulnerabilities
