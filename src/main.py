import yaml
import docker
import click

from core.run_containers import run_tools
from config.banner.banner import print_banner
from core.technology_detection.detect_technologies import detect_technologies

from report.report import generate_report

VERSION = '1.0.0'

#volume = "/home/julian/workspace/fafnir/src"

password = "ajklawejrkl42348swfgkg"

@click.command()
@click.argument('scan_fullpath')
@click.option("--verbose", is_flag=True, show_default=True, default=False, help="Verbose mode")
@click.option("--configuration", help="Fafnir configuration file")
@click.option("--asynchronous", is_flag=True, show_default=True, default=False, help="Asynchronous mode (run multiple containers at same time)")
def main(scan_fullpath, verbose, configuration, asynchronous):

    print_banner(VERSION)

    client = docker.from_env()

    config = yaml.safe_load(open("src/config/config.yml"))

    if configuration:
        fafnir_config = yaml.safe_load(open(configuration))
    else:
        fafnir_config = None

    print(detect_technologies(scan_fullpath))

    run_tools(client, config, scan_fullpath, verbose, fafnir_config, asynchronous)

    generate_report(scan_fullpath)

# Main program
if __name__ == '__main__':
    main()