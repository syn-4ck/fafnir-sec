import os
import json

from ..parsers.gitleaks_parser import parse_gitleaks_vulns
from ..parsers.semgrep_parser import parse_semgrep_vulns
from ..parsers.trivy_sca_parser import parse_trivy_sca_vulns
from ..parsers.trivy_container_parser import parse_trivy_container_vulns
from ..parsers.checkov_parser import parse_checkov_vulns
from ..parsers.osv_scanner_parser import parse_osv_scanner_vulns
from ..parsers.bandit_parser import parse_bandit_vulns

def process(scan_fullpath):
    vulnerabilities = []
    if os.path.exists(os.path.normpath(scan_fullpath + "/security-tools/semgrep/semgrep_results.json")):
        with open(os.path.normpath(scan_fullpath + "/security-tools/semgrep/semgrep_results.json"), 'r') as semgrep_file:
            vulnerabilities.append(parse_semgrep_vulns(json.loads(semgrep_file.read())))
    if os.path.exists(os.path.normpath(scan_fullpath + "/security-tools/trivy-sca/trivy-sca_results.json")):
        with open(os.path.normpath(scan_fullpath + "/security-tools/trivy-sca/trivy-sca_results.json"), 'r') as trivy_sca_file:
            vulnerabilities.append(parse_trivy_sca_vulns(json.loads(trivy_sca_file.read())))
    if os.path.exists(os.path.normpath(scan_fullpath + "/security-tools/trivy-container/trivy-container_results.json")):
        with open(os.path.normpath(scan_fullpath + "/security-tools/trivy-container/trivy-container_results.json"), 'r') as trivy_container_file:
            vulnerabilities.append(parse_trivy_container_vulns(json.loads(trivy_container_file.read())))
    if os.path.exists(os.path.normpath(scan_fullpath + "/security-tools/gitleaks/gitleaks_results.json")):
        with open(os.path.normpath(scan_fullpath + "/security-tools/gitleaks/gitleaks_results.json"), 'r') as gitleaks_file:
            vulnerabilities.append(parse_gitleaks_vulns(json.loads(gitleaks_file.read())))
    if os.path.exists(os.path.normpath(scan_fullpath + "/security-tools/checkov/results_json.json")):
        with open(os.path.normpath(scan_fullpath + "/security-tools/checkov/results_json.json"), 'r') as checkov_file:
            vulnerabilities.append(parse_checkov_vulns(json.loads(checkov_file.read())))
    if os.path.exists(os.path.normpath(scan_fullpath + "/security-tools/osv-scanner/osv-scanner_results.json")):
        with open(os.path.normpath(scan_fullpath + "/security-tools/osv-scanner/osv-scanner_results.json"), 'r') as osv_scanner_file:
            vulnerabilities.append(parse_osv_scanner_vulns(json.loads(osv_scanner_file.read())))
    if os.path.exists(os.path.normpath(scan_fullpath + "/security-tools/bandit/bandit_results.json")):
        with open(os.path.normpath(scan_fullpath + "/security-tools/bandit/bandit_results.json"), 'r') as bandit_file:
            vulnerabilities.append(parse_bandit_vulns(json.loads(bandit_file.read())))
    return [item for sublist in vulnerabilities for item in sublist]