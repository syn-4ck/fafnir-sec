from report.data_schema.dependency import Dependency

def parse_syft_vulns(report: dict):
    dependencies = []
    for artifact in report.get('artifacts'):
        dependencies.append(Dependency(artifact.get('name'), artifact.get('version'),[location.get('path') for location in artifact.get('locations')],
                                       artifact.get('type'),artifact.get('language'),[lic.get('value') for lic in artifact.get('licenses')],artifact.get('purl')))
    return dependencies