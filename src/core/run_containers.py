#import logging
import itertools
import os
from time import sleep

def _setup_environment_vars(configuration, tool):
    if tool == "semgrep":
        if configuration.get('tools-config').get('semgrep') is not None and configuration.get('tools-config').get('semgrep').get('api-key') is not None:
            return ["SEMGREP_APP_TOKEN={}".format(configuration.get('tools-config').get('semgrep').get('api-key'))]
        else:
            print('Semgrep api-key is not setted properly. Please, review the documentation of the fafnir configuration.')
            return []
    elif tool == "checkov":
        if configuration.get('tools-config').get('checkov') is not None and configuration.get('tools-config').get('checkov').get('api-key') is not None:
            return ["BC_API_KEY={}".format(configuration.get('tools-config').get('checkov').get('api-key'))]
        else:
            print('Checkov api-key is not setted properly. The tool will evaluate the vulnerabilities, but the data will not be completed.')
            return []
    else:
        return []

def _run_containers(client, tool, image, command, scan_fullpath, verbose, async_option, output_path, configuration):

    print(f"Running {tool} scanning...")

    environment_vars = _setup_environment_vars(configuration, tool)

    if environment_vars:
        container = client.containers.run(image, command, volumes={scan_fullpath:{"bind":"/src", "mode":"rw"}, output_path:{"bind":"/report", "mode":"rw"}}, environment=environment_vars,detach=True, stdout=True)
    else:
        container = client.containers.run(image, command, volumes={scan_fullpath:{"bind":"/src", "mode":"rw"}, output_path:{"bind":"/report", "mode":"rw"}},detach=True, stdout=True)

    if verbose and not async_option:
        try:
            container_logs = container.logs(stream = True)
            while True:
                line = next(container_logs).decode("utf-8")
                print(line)
        except StopIteration:
            print(f'{tool} execution finished')
    else:
        if not async_option:
            for c in itertools.cycle('/-\|'):
                print(c, end = '\r')
                sleep(0.2)
                if client.containers.get(container.id).status == "exited":
                    break
    
    return container.id

def run_tools(client, config, scan_fullpath, verbose, configuration, async_option, output_path, tools):
    container_ids = []
    if not os.path.exists(os.path.normpath(scan_fullpath + "/security-tools")):
        os.mkdir(os.path.normpath(scan_fullpath + "/security-tools"))
    
    # Run Security tools
    print("Running the Application security analysis")
    for category in config.get("containers").get("security-tools"):
        for tool in config.get("containers").get("security-tools").get(category):
            if tool in tools:
                if not os.path.exists(os.path.normpath(output_path + "/security-tools/" + tool)):
                    os.makedirs(os.path.normpath(output_path + "/security-tools/" + tool))
                tool_config = config.get("containers").get("security-tools").get(category).get(tool)
                tool_image = "{img}:{version}".format(img=tool_config.get("image"),version=tool_config.get("version"))
                tool_command = tool_config.get("command")

                container_ids.append(_run_containers(client, tool, tool_image, tool_command, scan_fullpath, verbose, async_option, output_path, configuration))
    
    # Run Continer tools
    if configuration is None or configuration.get("containers") is None or configuration.get("containers").get("image") is None or configuration.get("containers").get("image") == "":
        print("Container security not enabled. Please, set up the image name in Fafnir configuration to evaluate it")
    else:
        print("Running the Container security analysis")
        for tool in config.get("containers").get("container-security"):
            if not os.path.exists(os.path.normpath(output_path + "/security-tools/" + tool)):
                os.makedirs(os.path.normpath(output_path + "/security-tools/" + tool))
            tool_config = config.get("containers").get("container-security").get(tool)
            tool_image = "{img}:{version}".format(img=tool_config.get("image"),version=tool_config.get("version"))
            tool_command = tool_config.get("command").format(configuration.get("containers").get("image"))
            container_ids.append(_run_containers(client, tool, tool_image, tool_command, scan_fullpath, verbose, async_option, output_path, configuration))

    if async_option:
        while len(container_ids) > 0:
            for container_id in container_ids:
                print("\nProcessing all scans...")
                for c in itertools.cycle('/-\|'):
                    print(c, end = '\r')
                    sleep(0.2)
                    if client.containers.get(container_id).status == "exited":
                        container_ids.remove(container_id)
                        break