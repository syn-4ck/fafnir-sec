import os

from typing import List, Dict


def _detect_technologies(code_path: str) -> List[str]:
    """
    Detects the programming technologies used in the given code path.

    Args:
        code_path: The path to the directory containing the code.

    Returns:
        A list of programming technologies used in the code.
    """
    return list(set(_guess_programming_language_from_extension(os.path.join(root, f))
                    for root, _, f_names in os.walk(code_path)
                    for f in f_names
                    if _guess_programming_language_from_extension(os.path.join(root, f))))


def _guess_programming_language_from_extension(filepath: str) -> str:
    """
    Guesses the programming language based on the file extension of the given file path.

    Parameters:
        filepath (str): The path of the file.

    Returns:
        str: The file extension indicating the programming language.
    """
    _, file_extension = os.path.splitext(filepath)
    return file_extension


def select_tools(scan_fullpath: str, config: Dict[str, dict], fafnir_configuration: Dict[str, list]) -> List[str]:
    """
    Generates a list of tools based on the detected technologies in the given scan_fullpath.

    Parameters:
    - scan_fullpath (str): The full path of the scan.
    - config (Dict[str, dict]): The configuration dictionary.
    - fafnir_configuration (Dict[str, list]): The fafnir configuration dictionary.

    Returns:
    - list[str]: A list of tools based on the detected technologies, excluding any tools specified in the fafnir configuration.

    """
    technologies = _detect_technologies(scan_fullpath)
    exclude_tools = fafnir_configuration.get('exclude-tools', [])

    list_tools = [
        tool
        for tech in config.get('technologies').keys()
        for code_technology in technologies
        if code_technology in config.get('technologies').get(tech).get('extensions')
        for tool in config.get('technologies').get(tech).get('tools')
        if tool not in exclude_tools
    ]

    return list_tools
