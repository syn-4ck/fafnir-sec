from typing import List, Dict

from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Static Application Security Testing (SAST)"
TOOL_NAME = "FindSecBugs"
FIELDS_NOT_DEFINED = "Not defined by the tool"

def _get_findsecbugs_severity(level):
    """
    Get the severity level for FindSecBugs.

    :param level: The level of severity for FindSecBugs.
    :return: The corresponding severity level for FindSecBugs.
    """
    return {
        "warning": "HIGH",
        "error": "CRITICAL"
    }.get(level, level)

def get_physical_location(item):
    """
    Retrieve the physical location of an item.

    Parameters:
        item (dict): A dictionary representing an item.

    Returns:
        str or None: The URI of the artifact location if it exists, None otherwise.
    """
    physical_location = item.get('physicalLocation')
    if physical_location is not None:
        artifact_location = physical_location.get('artifactLocation')
        if artifact_location is not None:
            return artifact_location.get('uri')
    return None

def get_region_start_line(item):
    """
    Get the start line of the region from the given item.

    Args:
        item (dict): The item containing the physical location.

    Returns:
        int or None: The start line of the region, or None if not found.
    """
    physical_location = item.get('physicalLocation')
    if physical_location is not None:
        region = physical_location.get('region')
        if region is not None:
            return region.get('startLine')
    return None

def parse_findsecbugs_vulns(report: Dict[str, List[Dict[str, object]]]) -> List[Vulnerability]:
    """
    Parses the FindSecBugs vulnerabilities from the given report.

    Args:
        report (Dict[str, List[Dict[str, object]]]): The report containing the FindSecBugs vulnerabilities.

    Returns:
        List[Vulnerability]: A list of Vulnerability objects representing the parsed vulnerabilities.
    """

    vulnerabilities: List[Vulnerability] = []
    for run in report.get('runs'):
        for result in run.get('results',[]):
            try: 
                files = [get_physical_location(item) for item in result.get('locations') if get_physical_location(item) is not None]
                locations = [get_region_start_line(item) for item in result.get('locations') if get_region_start_line(item) is not None]
                message = result.get('message').get('text')
                rule_id = result.get('ruleId')
                severity = _get_findsecbugs_severity(result.get('level'))
                file = files[0] if files else "Not detected"
                location = locations[0] if locations else 0
                fix = FIELDS_NOT_DEFINED
                link = FIELDS_NOT_DEFINED
                vulnerability = Vulnerability()
                vulnerability.set_name(message)
                vulnerability.set_description(rule_id + ": " + message)
                vulnerability.set_identifier(rule_id)
                vulnerability.set_severity(severity)
                vulnerability.set_cvss(None)
                vulnerability.set_epss(None)
                vulnerability.set_category(CATEGORY)
                vulnerability.set_rule(rule_id)
                vulnerability.set_file(file)
                vulnerability.set_location(location)
                vulnerability.set_fix(fix)
                vulnerability.set_link(link)
                vulnerability.set_tools([TOOL_NAME])
                vulnerabilities.append(vulnerability)
            except Exception as e:
                print(f"Error parsing vulnerability: {e}")
    return vulnerabilities
