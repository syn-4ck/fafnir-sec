from typing import List, Dict

from ..data_schema.vulnerability import Vulnerability

CATEGORY = "Software Compose Analysis (SCA)"
TOOL_NAME = "OSV Scanner"


def _get_real_severity(severity):
    """
    Return the real severity based on the input severity.

    Parameters:
        severity (str): The input severity value.

    Returns:
        str: The real severity value.
    """
    return "High" if severity in ("MODERATE", "HIGH") else severity


def _get_fix_version(affected_versions):
    """
    Returns a list of fix versions based on the provided affected versions.

    Parameters:
        affected_versions (list): A list of affected versions.

    Returns:
        list: A list of fix versions.
    """
    fix_version = []
    for version in affected_versions:
        for range in version['ranges']:
            for event in range['events']:
                fixed = event.get('fixed')
                if fixed and fixed not in fix_version:
                    fix_version.append(fixed)
    return fix_version


def parse_osv_scanner_vulns(report: Dict[str, List[Dict[str, List[Dict[str, str]]]]]) -> List[Vulnerability]:
    """
    Parse the vulnerabilities from the OSV scanner report.

    Args:
        report (dict): The OSV scanner report.

    Returns:
        list: A list of Vulnerability objects.
    """
    vulnerabilities = []
    results = report.get('results', [])
    if results:
        for result in results:
            vulns = [vuln
                     for package in result.get('packages')
                     for vuln in package.get('vulnerabilities')]

            for vuln in vulns:
                vuln_id = next((alias for alias in vuln.get('aliases')
                                if alias.startswith('CVE-')), vuln.get('id'))
                affected = vuln.get('affected')
                fix_version = _get_fix_version(affected)
                db_specific = vuln.get('database_specific')
                vuln_severity = _get_real_severity(db_specific.get('severity'))
                package_name = vuln.get('package', {}).get('name')
                summary = vuln.get('summary')
                details = vuln.get('details')
                references = vuln.get('references')
                severity = vuln['severity'][0]['score']

                vulnerability = Vulnerability()
                vulnerability.set_name(
                    f"{vuln_id} ({package_name}): {summary}")
                vulnerability.set_description(details)
                vulnerability.set_identifier(vuln_id)
                vulnerability.set_severity(vuln_severity)
                vulnerability.set_cvss(severity)
                vulnerability.set_epss(None)
                vulnerability.set_category(CATEGORY)
                vulnerability.set_rule(vuln_id)
                vulnerability.set_file(result.get('source', {}).get('path'))
                vulnerability.set_location(1)
                vulnerability.set_fix(fix_version)
                vulnerability.set_link(references[0]['url'])
                vulnerability.set_tools([TOOL_NAME])

                vulnerabilities.append(vulnerability)

    return vulnerabilities
