import yaml
import docker
import click

from core.run_containers import run_tools
from config.banner.banner import print_banner

VERSION = '1.0.0'

#volume = "/home/julian/workspace/fafnir/src"

@click.command()
@click.argument('scan_fullpath')
@click.option("--verbose", is_flag=True, show_default=True, default=False, help="Verbose mode")
@click.option("--configuration", help="Fafnir configuration file")
def main(scan_fullpath, verbose, configuration):

    print_banner(VERSION)

    client = docker.from_env()

    config = yaml.safe_load(open("src/config/config.yml"))

    if configuration:
        fafnir_config = yaml.safe_load(open(configuration))
    else:
        fafnir_config = None

    run_tools(client, config, scan_fullpath, verbose, fafnir_config)

# Main program
if __name__ == '__main__':
    main()