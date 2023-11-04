from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Static Application Security Testing (SAST)"
TOOL_NAME = "FindSecBugs"

def _get_findsecbugs_severity(level):
    if level == "warning":
        return "HIGH"
    elif level == "error":
        return "CRITICAL"
    else:
        return level

def parse_findsecbugs_vulns(report: dict):
    vulnerabilities = []
    for run in report.get('runs'):
        for result in run.get('results'):
            files = [item.get('physicalLocation').get('artifactLocation').get('uri') for item in result.get('locations') if item.get('physicalLocation') is not None and item.get('physicalLocation').get('artifactLocation') is not None]
            locations = [item.get('physicalLocation').get('region').get('startLine') for item in result.get('locations') if item.get('physicalLocation') is not None and item.get('physicalLocation').get('region') is not None]
            vulnerabilities.append(Vulnerability(result.get('message').get('text'), result.get('ruleId') + ": " + result.get('message').get('text'),"Not defined by the tool",
                                                 _get_findsecbugs_severity(result.get('level')), "N/A", "N/A", CATEGORY, result.get('ruleId'), files[0] if files else "Not detected",
                                                 locations[0] if locations else 0, "Not defined by the tool", "Not defined by the tool",[TOOL_NAME]))
    return vulnerabilities