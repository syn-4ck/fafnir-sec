#import logging
import itertools
import os
from time import sleep

def run_tools(client, config, scan_fullpath, verbose, configuration):
    if not os.path.exists(os.path.normpath(scan_fullpath + "/security-tools")):
        os.mkdir(os.path.normpath(scan_fullpath + "/security-tools"))
    for category in config.get("containers").get("security-tools"):
        for tool in config.get("containers").get("security-tools").get(category):
            if configuration is None or tool in configuration.get("exclude-tools"):
                tool_config = config.get("containers").get("security-tools").get(category).get(tool)
                tool_image = "{img}:{version}".format(img=tool_config.get("image"),version=tool_config.get("version"))
                tool_command = tool_config.get("command")

                _run_containers(client, tool, tool_image, tool_command, scan_fullpath, verbose)
            else:
                print(f"Skipping {tool}...")

def _run_containers(client, tool, image, command, volume, verbose):

    print(f"Running {tool} scanning...")

    container = client.containers.run(image, command, volumes={volume: {"bind":"/src", "mode":"rw"}}, detach=True, stdout=True)

    if verbose:
        try:
            container_logs = container.logs(stream = True)
            while True:
                line = next(container_logs).decode("utf-8")
                print(line)
        except StopIteration:
            print(f'{tool} execution finished')
    else:
        for c in itertools.cycle('/-\|'):
            print(c, end = '\r')
            sleep(0.2)
            if client.containers.get(container.id).status == "exited":
                break