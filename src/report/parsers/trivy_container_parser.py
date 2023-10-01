from report.data_schema.vulnerability import Vulnerability

CATEGORY = "Container analysis"
TOOL_NAME = "Trivy"

def parse_trivy_container_vulns(report: dict):
    vulnerabilities = []
    for source in report.get('Results'):
        for vuln in source.get('Vulnerabilities'):
            name = vuln.get('VulnerabilityID') + " (" + vuln.get('PkgName') + "): " + vuln.get('Title')
            vulnerabilities.append(Vulnerability(name, vuln.get('Description'),vuln.get('VulnerabilityID'),vuln.get('Severity'),vuln.get('CVSS').get('nvd').get('V3Score'), "N/A",
                                      CATEGORY, "N/A", source.get('Target'),
                                      vuln.get('PkgName') + "@" + vuln.get('InstalledVersion'),vuln.get('FixedVersion'),vuln.get('PrimaryURL'),TOOL_NAME))
    return vulnerabilities