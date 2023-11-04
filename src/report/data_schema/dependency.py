
class Dependency:

    def __init__(self, name, version, location, package_manager, language, licenses, purl):
        self.name = name
        self.version = version
        self.location = location
        self.package_manager = package_manager
        self.language = language
        self.licenses = licenses
        self.purl = purl