import os
import json
import re
import requests
from cvss import CVSS3

from ..parsers.syft_parser import parse_syft_vulns

from ..parsers.gitleaks_parser import parse_gitleaks_vulns
from ..parsers.semgrep_parser import parse_semgrep_vulns
from ..parsers.trivy_sca_parser import parse_trivy_sca_vulns
from ..parsers.trivy_container_parser import parse_trivy_container_vulns
from ..parsers.checkov_parser import parse_checkov_vulns
from ..parsers.osv_scanner_parser import parse_osv_scanner_vulns
from ..parsers.bandit_parser import parse_bandit_vulns
from ..parsers.findsecbugs_parser import parse_findsecbugs_vulns

def process_vulns(output_path, disable_apis):
    vulnerabilities = []
    if os.path.exists(os.path.normpath(output_path + "/security-tools/semgrep/semgrep_results.json")):
        with open(os.path.normpath(output_path + "/security-tools/semgrep/semgrep_results.json"), 'r') as semgrep_file:
            vulnerabilities.append(parse_semgrep_vulns(json.loads(semgrep_file.read())))
    if os.path.exists(os.path.normpath(output_path + "/security-tools/trivy-sca/trivy-sca_results.json")):
        with open(os.path.normpath(output_path + "/security-tools/trivy-sca/trivy-sca_results.json"), 'r') as trivy_sca_file:
            vulnerabilities.append(parse_trivy_sca_vulns(json.loads(trivy_sca_file.read())))
    if os.path.exists(os.path.normpath(output_path + "/security-tools/trivy-container/trivy-container_results.json")):
        with open(os.path.normpath(output_path + "/security-tools/trivy-container/trivy-container_results.json"), 'r') as trivy_container_file:
            vulnerabilities.append(parse_trivy_container_vulns(json.loads(trivy_container_file.read())))
    if os.path.exists(os.path.normpath(output_path + "/security-tools/gitleaks/gitleaks_results.json")):
        with open(os.path.normpath(output_path + "/security-tools/gitleaks/gitleaks_results.json"), 'r') as gitleaks_file:
            vulnerabilities.append(parse_gitleaks_vulns(json.loads(gitleaks_file.read())))
    if os.path.exists(os.path.normpath(output_path + "/security-tools/checkov/results_json.json")):
        with open(os.path.normpath(output_path + "/security-tools/checkov/results_json.json"), 'r') as checkov_file:
            vulnerabilities.append(parse_checkov_vulns(json.loads(checkov_file.read())))
    if os.path.exists(os.path.normpath(output_path + "/security-tools/osv-scanner/osv-scanner_results.json")):
        with open(os.path.normpath(output_path + "/security-tools/osv-scanner/osv-scanner_results.json"), 'r') as osv_scanner_file:
            if os.stat(output_path + "/security-tools/osv-scanner/osv-scanner_results.json").st_size == 0:
                osv_data = {}
            else:
                osv_data = json.loads(osv_scanner_file.read())
            vulnerabilities.append(parse_osv_scanner_vulns(osv_data))
    if os.path.exists(os.path.normpath(output_path + "/security-tools/bandit/bandit_results.json")):
        with open(os.path.normpath(output_path + "/security-tools/bandit/bandit_results.json"), 'r') as bandit_file:
            vulnerabilities.append(parse_bandit_vulns(json.loads(bandit_file.read())))
    if os.path.exists(os.path.normpath(output_path + "/security-tools/find-sec-bugs/findsecbugs_results.sarif")):
        with open(os.path.normpath(output_path + "/security-tools/find-sec-bugs/findsecbugs_results.sarif"), 'r') as findsecbugs_file:
            vulnerabilities.append(parse_findsecbugs_vulns(json.loads(findsecbugs_file.read())))
    
    if disable_apis:
        pattern = re.compile("^CVE-[0-9-]+")
        pattern_cve_string = re.compile("^CVSS:3.*")
        for item in [item for sublist in vulnerabilities for item in sublist]:
            if item.identifier and pattern.match(item.identifier):
                if pattern_cve_string.match(str(item.cvss)):
                    c = CVSS3(item.cvss)
                    item.cvss = max(list(c.scores()))
                    idx = list(c.scores()).index(max(list(c.scores())))
                    item.severity = list(c.severities())[idx].upper()
                epss_response = requests.get(f"https://api.first.org/data/v1/epss?cve={item.identifier}")
                if epss_response.status_code == 200:
                    epss_object = epss_response.json()
                    item.epss = epss_object.get('data')[0].get('epss')

    return [item for sublist in vulnerabilities for item in sublist]

def process_deps(output_path):
    dependencies = []
    if os.path.exists(os.path.normpath(output_path + "/security-tools/syft/syft_results.json")):
        with open(os.path.normpath(output_path + "/security-tools/syft/syft_results.json"), 'r') as syft_file:
            dependencies.append(parse_syft_vulns(json.loads(syft_file.read())))
    return [item.__dict__ for sublist in dependencies for item in sublist]