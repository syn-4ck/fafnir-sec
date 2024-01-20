import yaml
import docker
import click
import os
from typing import Optional
import logging

from .core.run_containers import run_tools
from .config.banner.banner import print_banner
from .core.technology_detection.detect_technologies import select_tools

from .report.report import generate_report

VERSION = '1.0.0'


@click.command()
@click.argument('scan_fullpath')
@click.option("-v", "--verbose", is_flag=True, show_default=True, default=False, help="Verbose mode")
@click.option("-c", "--configuration", help="Fafnir configuration file")
@click.option("-a", "--asynchronous", is_flag=True, show_default=True, default=False, help="Asynchronous mode")
@click.option("-t", "--output-type", type=click.Choice(['json', 'sarif']), default="json", help="Report type")
@click.option("-o", "--output-path", default=os.path.join(os.path.abspath("."), "reports"), help="Path to store the tools/Fafnir report")
@click.option("-x","--disable-apis", is_flag=True, show_default=True, default=True, help="Disable API requests")
def main(scan_fullpath: str, verbose: bool, configuration: Optional[str],
         asynchronous: bool, output_type: str, output_path: str, disable_apis: bool) -> None:

    print_banner(VERSION)

    if verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s: %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(levelname)s - %(message)s')

    client = docker.from_env()

    logging.info('Configuring Fafnir...')
    config = yaml.safe_load(open("src/config/config.yml"))
    fafnir_config = yaml.safe_load(
        open(configuration)) if configuration else None

    logging.info('Detecting technologies...')
    tools = select_tools(os.path.abspath(scan_fullpath), config, fafnir_config)

    logging.info('Running security analysis...')
    run_tools(client, config, os.path.abspath(scan_fullpath), verbose,
              fafnir_config, asynchronous, output_path, tools)

    logging.info('Generating report...')
    generate_report(scan_fullpath, output_type, output_path, disable_apis)


# Main program
if __name__ == '__main__':
    main()
