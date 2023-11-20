import yaml
import docker
import click
import os
from typing import Optional

from core.run_containers import run_tools
from config.banner.banner import print_banner
from core.technology_detection.detect_technologies import select_tools

from report.report import generate_report

VERSION = '1.0.0'

@click.command()
@click.argument('scan_fullpath')
@click.option("--verbose", is_flag=True, show_default=True, default=False, help="Verbose mode")
@click.option("--configuration", help="Fafnir configuration file")
@click.option("--asynchronous", is_flag=True, show_default=True, default=False, help="Asynchronous mode")
@click.option("--output-path", default=os.path.join(os.path.abspath("."),"reports"), help="Path to store the tools/Fafnir report")
@click.option("--disable-apis", is_flag=True, show_default=True, default=True, help="Disable API requests")
def main(scan_fullpath: str, verbose: bool, configuration: Optional[str], 
         asynchronous: bool, output_path: str, disable_apis: bool) -> None:
    """
    Run the main function of the program.

    Args:
        scan_fullpath (str): The full path of the scan.
        verbose (bool): Flag indicating whether to run in verbose mode.
        configuration (str): The file path of the Fafnir configuration file.
        asynchronous (bool): Flag indicating whether to run in asynchronous mode.
        output_path (str): The path to store the Fafnir report.
        disable_apis (bool): Flag indicating whether to disable API requests.

    Returns:
        None
    """

    print_banner(VERSION)

    client = docker.from_env()

    config = yaml.safe_load(open("src/config/config.yml"))

    fafnir_config = yaml.safe_load(open(configuration)) if configuration else None

    tools = select_tools(scan_fullpath, config, fafnir_config)

    run_tools(client, config, scan_fullpath, verbose, fafnir_config, asynchronous, output_path, tools)

    generate_report(output_path, disable_apis)

# Main program
if __name__ == '__main__':
    main()