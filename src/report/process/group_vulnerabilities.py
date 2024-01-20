from typing import List, Dict

from ..data_schema.vulnerability import Vulnerability


def group_sast_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Dict[str, str]]:
    """
    Group SAST vulnerabilities based on file and location.

    Args:
        vulnerabilities: A list of Vulnerability objects representing individual vulnerabilities.

    Returns:
        A list of dictionaries representing grouped vulnerabilities, with each dictionary containing the attributes of a Vulnerability object.

    """
    grouped_vulnerabilities: List[Vulnerability] = []
    for vuln in vulnerabilities:
        added = False
        for grouped_vuln in grouped_vulnerabilities:
            if (
                grouped_vuln.file == vuln.file
                and grouped_vuln.location == vuln.location
            ):
                if vuln.tools[0] not in grouped_vuln.tools:
                    grouped_vuln.set_tools(grouped_vuln.get_tools().append((vuln.tools[0])))
                added = True
                break
        if not added:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]


def group_sca_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Dict[str, str]]:
    """
    Group SCA vulnerabilities based on identifier, file, and location.

    Args:
        vulnerabilities: A list of Vulnerability objects representing individual vulnerabilities.

    Returns:
        A list of dictionaries representing grouped vulnerabilities, with each dictionary containing the attributes of a Vulnerability object.
    """
    grouped_vulnerabilities: List[Vulnerability] = []
    for vuln in vulnerabilities:
        added = False
        for grouped_vuln in grouped_vulnerabilities:
            if (
                grouped_vuln.identifier == vuln.identifier
                and grouped_vuln.file == vuln.file
                and grouped_vuln.location == vuln.location
            ):
                if vuln.tools[0] not in grouped_vuln.tools:
                    grouped_vuln.set_tools(grouped_vuln.get_tools().append((vuln.tools[0])))
                added = True
                break
        if not added:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]


def group_container_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Dict[str, str]]:
    """
    Group container vulnerabilities based on identifier, file, and location.

    Args:
        vulnerabilities: A list of Vulnerability objects representing individual vulnerabilities.

    Returns:
        A list of dictionaries representing grouped vulnerabilities, with each dictionary containing the attributes of a Vulnerability object.
    """
    grouped_vulnerabilities: List[Vulnerability] = []
    for vuln in vulnerabilities:
        added = False
        for grouped_vuln in grouped_vulnerabilities:
            if (
                grouped_vuln.identifier == vuln.identifier
                and grouped_vuln.file == vuln.file
                and grouped_vuln.location == vuln.location
            ):
                if vuln.tools[0] not in grouped_vuln.tools:
                    grouped_vuln.set_tools(grouped_vuln.get_tools().append((vuln.tools[0])))
                added = True
                break
        if not added:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]


def group_iac_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Dict[str, str]]:
    """
    Group IAC vulnerabilities based on identifier, file, and location.

    Args:
        vulnerabilities: A list of Vulnerability objects representing individual vulnerabilities.

    Returns:
        A list of dictionaries representing grouped vulnerabilities, with each dictionary containing the attributes of a Vulnerability object.
    """
    grouped_vulnerabilities: List[Vulnerability] = []
    for vuln in vulnerabilities:
        added = False
        for grouped_vuln in grouped_vulnerabilities:
            if (
                grouped_vuln.identifier == vuln.identifier
                and grouped_vuln.file == vuln.file
                and grouped_vuln.location == vuln.location
            ):
                if vuln.tools[0] not in grouped_vuln.tools:
                    grouped_vuln.set_tools(grouped_vuln.get_tools().append((vuln.tools[0])))
                added = True
                break
        if not added:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]


def group_secrets_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Dict[str, str]]:
    """
    Group secrets vulnerabilities based on identifier, file, and location.

    Args:
        vulnerabilities: A list of Vulnerability objects representing individual vulnerabilities.

    Returns:
        A list of dictionaries representing grouped vulnerabilities, with each dictionary containing the attributes of a Vulnerability object.
    """
    grouped_vulnerabilities: List[Vulnerability] = []
    for vuln in vulnerabilities:
        added = False
        for grouped_vuln in grouped_vulnerabilities:
            if (
                grouped_vuln.file == vuln.file
                and grouped_vuln.location == vuln.location
            ):
                if vuln.tools[0] not in grouped_vuln.tools:
                    grouped_vuln.set_tools(grouped_vuln.get_tools().append((vuln.tools[0])))
                added = True
                break
        if not added:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]