import os
import json
import re
import requests
from cvss import CVSS3
from typing import List, Callable, Any, Dict
import logging

from ..parsers.syft_parser import parse_syft_vulns

from ..parsers.gitleaks_parser import parse_gitleaks_vulns
from ..parsers.semgrep_parser import parse_semgrep_vulns
from ..parsers.trivy_sca_parser import parse_trivy_sca_vulns
from ..parsers.trivy_container_parser import parse_trivy_container_vulns
from ..parsers.checkov_parser import parse_checkov_vulns
from ..parsers.osv_scanner_parser import parse_osv_scanner_vulns
from ..parsers.bandit_parser import parse_bandit_vulns
from ..parsers.findsecbugs_parser import parse_findsecbugs_vulns


def _check_and_parse(file_path: str, parse_function: Callable[[str], Any], vulnerabilities: List[Any]) -> None:
    """
    Check if the file path exists and parse the file contents using the provided parse function.

    Args:
        file_path: The path to the file to be checked and parsed.
        parse_function: The function used to parse the file contents.
        vulnerabilities: A list to store the parsed vulnerabilities.

    Returns:
        None
    """
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            vulnerabilities.append(parse_function(json.loads(file.read())))


def process_vulns(output_path: str, disable_apis: bool) -> List:
    """
    Process the vulnerabilities from various security tools and return a list of vulnerabilities.

    Args:
        output_path: The path to the output directory where the security tool results are stored.
        disable_apis: A flag indicating whether to disable certain APIs.

    Returns:
        A list of vulnerabilities.
    """
    vulnerabilities: List = []

    _check_and_parse(os.path.normpath(
        output_path + "/security-tools/semgrep/semgrep_results.json"), parse_semgrep_vulns, vulnerabilities)
    _check_and_parse(os.path.normpath(
        output_path + "/security-tools/trivy-sca/trivy-sca_results.json"), parse_trivy_sca_vulns, vulnerabilities)
    _check_and_parse(os.path.normpath(output_path + "/security-tools/trivy-container/trivy-container_results.json"),
                     parse_trivy_container_vulns, vulnerabilities)
    _check_and_parse(os.path.normpath(
        output_path + "/security-tools/gitleaks/gitleaks_results.json"), parse_gitleaks_vulns, vulnerabilities)
    _check_and_parse(os.path.normpath(
        output_path + "/security-tools/checkov/results_json.json"), parse_checkov_vulns, vulnerabilities)
    _check_and_parse(os.path.normpath(
        output_path + "/security-tools/osv-scanner/osv-scanner_results.json"), parse_osv_scanner_vulns, vulnerabilities)
    _check_and_parse(os.path.normpath(
        output_path + "/security-tools/bandit/bandit_results.json"), parse_bandit_vulns, vulnerabilities)
    _check_and_parse(os.path.normpath(
        output_path + "/security-tools/find-sec-bugs/findsecbugs_results.sarif"), parse_findsecbugs_vulns, vulnerabilities)

    if disable_apis:
        pattern = re.compile("^CVE-[0-9-]+")
        pattern_cve_string = re.compile("^CVSS:3.*")
        logging.info('Querying vulnerabilities EPSS...')
        for item in [item for sublist in vulnerabilities for item in sublist]:
            if item.get_identifier() and pattern.match(item.get_identifier()):
                if pattern_cve_string.match(str(item.get_cvss())):
                    c = CVSS3(item.get_cvss())
                    item.set_cvss(max(list(c.scores())))
                    idx = list(c.scores()).index(max(list(c.scores())))
                    item.set_severity(list(c.severities())[idx].upper())
                epss_response = requests.get(
                    f"https://api.first.org/data/v1/epss?cve={item.get_identifier()}")
                if epss_response.status_code == 200:
                    epss_object = epss_response.json()
                    if epss_object.get('data'):
                        item.set_epss(epss_object.get('data')[0].get('epss'))

    return [item for sublist in vulnerabilities for item in sublist]


def process_deps(output_path: str) -> List[Dict[str, str]]:
    """
    Generates a list of dependencies by parsing the results of the Syft security tool.

    Args:
        output_path: The path to the output directory.

    Returns:
        A list of dictionaries representing the dependencies and their properties.
    """
    syft_results_path = os.path.join(
        output_path, "security-tools", "syft", "syft_results.json")
    if os.path.exists(syft_results_path):
        with open(syft_results_path, 'r') as syft_file:
            dependencies = parse_syft_vulns(json.load(syft_file))
            return [item.__dict__ for item in dependencies]
    return []
