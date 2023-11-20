import json
import os
from typing import Dict, List

from .process.process_vulnerabilities import process_deps, process_vulns
from .process.group_vulnerabilities import group_sast_vulnerabilities, group_secrets_vulnerabilities, group_sca_vulnerabilities, group_iac_vulnerabilities, group_container_vulnerabilities
from report.data_schema.vulnerability import Vulnerability
from .data_schema.dependency import Dependency

def generate_report(output_path: str, disable_apis: bool) -> None:
    """
    Generates a report based on the specified output path and whether to disable certain APIs.

    :param output_path: The path where the report will be generated.
    :param disable_apis: Whether to disable certain APIs during the report generation.
    """
    vulnerabilities: List[Vulnerability] = process_vulns(output_path, disable_apis)
    dependencies: List[Dependency] = process_deps(output_path)

    secrets_vulnerabilities: Dict[str, List[Vulnerability]] = group_secrets_vulnerabilities([item for item in vulnerabilities if item.category == "Secrets detection"])
    sast_vulnerabilities: Dict[str, List[Vulnerability]] = group_sast_vulnerabilities([item for item in vulnerabilities if item.category == "Static Application Security Testing (SAST)"])
    sca_vulnerabilities: Dict[str, List[Vulnerability]] = group_sca_vulnerabilities([item for item in vulnerabilities if item.category == "Software Compose Analysis (SCA)"])
    containers_vulnerabilities: Dict[str, List[Vulnerability]] = group_container_vulnerabilities([item for item in vulnerabilities if item.category == "Container analysis"])
    iac_vulnerabilities: Dict[str, List[Vulnerability]] = group_iac_vulnerabilities([item for item in vulnerabilities if item.category == "IaC code analysis"])

    grouped_vulnerabilities: Dict[str, Dict[str, List[Vulnerability]]] = {
        "vulnerabilities": {
            "Static Application Security Testing (SAST)": sast_vulnerabilities,
            "Software Compose Analysis (SCA)": sca_vulnerabilities,
            "Container analysis": containers_vulnerabilities,
            "IaC code analysis": iac_vulnerabilities,
            "Secrets detection": secrets_vulnerabilities
        }
    }

    report: Dict[str, Dict[str, List[Vulnerability]]] = {
        "sbom": dependencies,
        "vulnerabilities": grouped_vulnerabilities
    }


    with open(os.path.normpath(output_path + "/security-tools/fafnir_report.json"), 'w') as vulns_json:
        vulns_json.write(json.dumps(report))
