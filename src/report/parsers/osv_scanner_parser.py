from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Software Compose Analysis (SCA)"
TOOL_NAME = "OSV Scanner"

def _get_real_severity(severity):
    if severity == "MODERATE" or severity == "HIGH":
        return "High"
    else:
        return severity

def _get_fix_version(affected_versions):
    fix_version = []
    for version in affected_versions:
        for range in version.get('ranges'):
            for event in range.get('events'):
                if event.get('fixed') and event.get('fixed') not in fix_version:
                    fix_version.append(event.get('fixed'))
    return fix_version

def parse_osv_scanner_vulns(report: dict):
    vulnerabilities = []
    if report.get('results'):
        for result in report.get('results'):
            for package in result.get('packages'):
                for vuln in package.get('vulnerabilities'):
                    vuln_id = vuln.get('id')
                    if vuln.get('aliases'):
                        for v in vuln.get('aliases'):
                            if v.startswith('CVE-'):
                                vuln_id = v
                    fix_version = _get_fix_version(vuln.get('affected'))
                    vuln_severity = _get_real_severity(vuln.get('database_specific').get('severity'))
                    name = vuln_id + " (" + package.get('package').get('name') + "): " + vuln.get('summary')
                    vulnerabilities.append(Vulnerability(name, vuln.get('details'),vuln_id, vuln_severity, vuln.get('severity')[0].get('score'), "N/A",
                                        CATEGORY, "N/A", result.get('source').get('path'), 
                                        package.get('package').get('name') + "@" + package.get('package').get('version'),
                                        fix_version,vuln.get('references')[0].get('url'),[TOOL_NAME]))
    return vulnerabilities