from typing import List, Dict

from report.data_schema.dependency import Dependency

def parse_syft_vulns(report: Dict[str, List[Dict[str, str]]]) -> List[Dependency]:
    """
    Parse the given `report` dictionary and extract information about vulnerabilities in the artifacts.

    Args:
        report (Dict[str, List[Dict[str, str]]]): A dictionary containing information about vulnerabilities in the artifacts.

    Returns:
        List[Dependency]: A list of Dependency objects representing the parsed vulnerabilities.
    """
    dependencies: List[Dependency] = []
    for artifact in report.get('artifacts',[]):
        dependency = Dependency()
        dependency.set_name(artifact.get('name'))
        dependency.set_version(artifact.get('version'))
        dependency.set_location([location.get('path') for location in artifact.get('locations')])
        dependency.set_package_manager(artifact.get('type'))
        dependency.set_language(artifact.get('language'))
        dependency.set_licenses([lic.get('value') for lic in artifact.get('licenses')])
        dependency.set_purl(artifact.get('purl'))
        dependencies.append(dependency)
    return dependencies
