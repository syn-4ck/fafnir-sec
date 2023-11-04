import os

#from guesslang import Guess

def _detect_technologies (code_path):
    technologies = []
    for root,_,f_names in os.walk(code_path):
        for f in f_names:
            tech = _guess_programming_language_from_extension(os.path.join(root, f))
            if tech is not None:
                technologies.append(tech)
    return list(dict.fromkeys(technologies))

def _guess_programming_language_from_extension (filepath):
    _, file_extension = os.path.splitext(filepath)
    return file_extension

def select_tools(scan_fullpath, config, fafnir_configuration):

    list_tools = []

    technologies = _detect_technologies(scan_fullpath)

    exclude_tools = []
    if fafnir_configuration.get('exclude-tools') is not None:
        exclude_tools = fafnir_configuration.get('exclude-tools')

    for tech in list(config.get('technologies').keys()):
        supported_technologies = config.get('technologies').get(tech).get('extensions')
        for code_technology in technologies:
            if code_technology in supported_technologies:
                list_tools.extend(x for x in config.get('technologies').get(tech).get('tools') if x not in list_tools and x not in exclude_tools)

    return list_tools

# Deprecated: Not so eficient
#def _guess_programming_language_from_file (filepath):
#    with open(filepath, 'r') as file:
#        file_content = file.read()
#        guess = Guess()
#        return guess.language_name(file_content)