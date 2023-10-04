import os

#from guesslang import Guess

def detect_technologies (code_path):
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

# Deprecated: Not so eficient
#def _guess_programming_language_from_file (filepath):
#    with open(filepath, 'r') as file:
#        file_content = file.read()
#        guess = Guess()
#        return guess.language_name(file_content)