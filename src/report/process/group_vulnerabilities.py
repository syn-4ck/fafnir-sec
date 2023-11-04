

def group_sast_vulnerabilities(vulnerabilities):
    grouped_vulnerabilities = []
    for vuln in vulnerabilities:
        if grouped_vulnerabilities != []:
            for grouped_vuln in grouped_vulnerabilities:
                if (grouped_vuln.file == vuln.file) and (grouped_vuln.location == vuln.location):
                    if vuln.tools[0] not in grouped_vuln.tools:
                        grouped_vuln.tools.append(vuln.tools)
            grouped_vulnerabilities.append(vuln)
        else:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]
    #return grouped_vulnerabilities

def group_sca_vulnerabilities(vulnerabilities):
    grouped_vulnerabilities = []
    for vuln in vulnerabilities:
        if grouped_vulnerabilities != []:
            for grouped_vuln in grouped_vulnerabilities:
                if (grouped_vuln.identifier == vuln.identifier) and (grouped_vuln.file == vuln.file) and (grouped_vuln.location == vuln.location):
                    if vuln.tools[0] not in grouped_vuln.tools:
                        grouped_vuln.tools.append(vuln.tools)
            grouped_vulnerabilities.append(vuln)
        else:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]
    #return grouped_vulnerabilities

def group_container_vulnerabilities(vulnerabilities):
    grouped_vulnerabilities = []
    for vuln in vulnerabilities:
        if grouped_vulnerabilities != []:
            for grouped_vuln in grouped_vulnerabilities:
                if (grouped_vuln.identifier == vuln.identifier) and (grouped_vuln.file == vuln.file) and (grouped_vuln.location == vuln.location):
                    if vuln.tools[0] not in grouped_vuln.tools:
                        grouped_vuln.tools.append(vuln.tools)
            grouped_vulnerabilities.append(vuln)
        else:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]
    #return grouped_vulnerabilities

def group_iac_vulnerabilities(vulnerabilities):
    grouped_vulnerabilities = []
    for vuln in vulnerabilities:
        if grouped_vulnerabilities != []:
            for grouped_vuln in grouped_vulnerabilities:
                if (grouped_vuln.identifier == vuln.identifier) and (grouped_vuln.file == vuln.file) and (grouped_vuln.location == vuln.location):
                    if vuln.tools[0] not in grouped_vuln.tools:
                        grouped_vuln.tools.append(vuln.tools)
            grouped_vulnerabilities.append(vuln)
        else:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]
    #return grouped_vulnerabilities


def group_secrets_vulnerabilities(vulnerabilities):
    grouped_vulnerabilities = []
    for vuln in vulnerabilities:
        if grouped_vulnerabilities != []:
            for grouped_vuln in grouped_vulnerabilities:
                if (grouped_vuln.file == vuln.file) and (grouped_vuln.location == vuln.location):
                    if vuln.tools[0] not in grouped_vuln.tools:
                        grouped_vuln.tools.append(vuln.tools)
            grouped_vulnerabilities.append(vuln)
        else:
            grouped_vulnerabilities.append(vuln)
    return [vuln.__dict__ for vuln in grouped_vulnerabilities]
    #return grouped_vulnerabilities