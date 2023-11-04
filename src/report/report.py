import json
import os

from .process.process_vulnerabilities import process_deps, process_vulns
from .process.group_vulnerabilities import group_sast_vulnerabilities, group_secrets_vulnerabilities, group_sca_vulnerabilities, group_iac_vulnerabilities, group_container_vulnerabilities

def generate_report(output_path, disable_apis):
    vulnerabilities = process_vulns(output_path, disable_apis)
    dependencies = process_deps(output_path)

    secrets_vulnerabilities = group_secrets_vulnerabilities([item for item in vulnerabilities if item.category == "Secrets detection"])
    sast_vulnerabilities = group_sast_vulnerabilities([item for item in vulnerabilities if item.category == "Static Application Security Testing (SAST)"])
    sca_vulnerabilities = group_sca_vulnerabilities([item for item in vulnerabilities if item.category == "Software Compose Analysis (SCA)"])
    containers_vulnerabilities = group_container_vulnerabilities([item for item in vulnerabilities if item.category == "Container analysis"])
    iac_vulnerabilities = group_iac_vulnerabilities([item for item in vulnerabilities if item.category == "IaC code analysis"])

    grouped_vulnerabilities = {
        "vulnerabilities": {
            "Static Application Security Testing (SAST)": sast_vulnerabilities,
            "Software Compose Analysis (SCA)": sca_vulnerabilities,
            "Container analysis": containers_vulnerabilities,
            "IaC code analysis": iac_vulnerabilities,
            "Secrets detection": secrets_vulnerabilities
        }
    }

    report = {
        "sbom": dependencies,
        "vulnerabilities": grouped_vulnerabilities
    }


    with open(os.path.normpath(output_path + "/security-tools/fafnir_report.json"), 'w') as vulns_json:
        vulns_json.write(json.dumps(report))
