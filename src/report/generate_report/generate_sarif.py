def generate_report_sarif(scan_fullpath: str, report: dict) -> dict:
    """
    Generates a SARIF report from the given report.

    Args:
        scan_fullpath (str): The full path of the scan.
        report (dict): The report to generate the SARIF report from.

    Returns:
        dict: The SARIF report.
    """
    sarif_report = {}

    sarif_report["version"] = "2.1.0"
    sarif_report["$schema"] = "http://json.schemastore.org/sarif-2.1.0-rtm.4"

    runs = []
    tools_results = {}
    if report.get("vulnerabilities").get("vulnerabilities"):
        for key in report.get("vulnerabilities").get("vulnerabilities"):
            for vuln in report.get("vulnerabilities").get("vulnerabilities").get(key):
                for tool in vuln.get("tools"):
                    result = {
                        "level": "error",
                        "message": {
                            "text": vuln.get("name")
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": vuln.get("file"),
                                        "index": 0
                                    },
                                    "region": {
                                        "startLine": vuln.get("location"),
                                        "startColumn": 1
                                    }
                                }
                            }
                        ],
                        "ruleId": vuln.get("rule"),
                        "ruleIndex": 0
                    }
                    if not tools_results.get(tool):
                        tools_results[tool] = []
                    tools_results[tool].append(result)
        for key, value in tools_results.items():
            runs.append({
                "tool": {
                    "driver": {
                        "name": key,
                        "informationUri": "",
                    }
                },
                "artifacts": [
                    {
                        "location": {
                            "uri": scan_fullpath,
                        }
                    }
                ],
                "results": value
            })

    sarif_report["runs"] = runs

    return sarif_report
