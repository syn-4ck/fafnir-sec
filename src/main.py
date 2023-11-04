import yaml
import docker
import click

from core.run_containers import run_tools
from config.banner.banner import print_banner
from core.technology_detection.detect_technologies import select_tools

from report.report import generate_report

VERSION = '1.0.0'

#volume = "/home/julian/workspace/fafnir/src"

@click.command()
@click.argument('scan_fullpath')
@click.option("--verbose", is_flag=True, show_default=True, default=False, help="Verbose mode")
@click.option("--configuration", help="Fafnir configuration file")
@click.option("--asynchronous", is_flag=True, show_default=True, default=False, help="Asynchronous mode (run multiple containers at same time)")
@click.option("--output-path", default=".", help="Path to store the tools/Fafnir report")
@click.option("--disable-apis", is_flag=True, show_default=True, default=True, help="Disable API requests")
def main(scan_fullpath, verbose, configuration, asynchronous, output_path, disable_apis):

    print_banner(VERSION)

    client = docker.from_env()

    config = yaml.safe_load(open("src/config/config.yml"))

    if configuration:
        fafnir_config = yaml.safe_load(open(configuration))
    else:
        fafnir_config = None

    tools = select_tools(scan_fullpath, config, fafnir_config)

    run_tools(client, config, scan_fullpath, verbose, fafnir_config, asynchronous, output_path, tools)

    generate_report(output_path, disable_apis)

# Main program
if __name__ == '__main__':
    main()