
class Dependency:

    def __init__(self) -> None:
        pass

    '''
    def __init__(self, name:str, version:str, location:str, package_manager:str, language, licenses, purl):
        self.name = name
        self.version = version
        self.location = location
        self.package_manager = package_manager
        self.language = language
        self.licenses = licenses
        self.purl = purl
    '''

    def get_name(self):
        """
        Get the name attribute.

        Returns:
            str: The name attribute.
        """
        return self.name

    def set_name(self, name):
        """
        Set the name attribute.

        Parameters:
            name (str): The new name attribute.

        Returns:
            None
        """
        self.name = name

    def get_version(self):
        """
        Get the version attribute.

        Returns:
            str: The version attribute.
        """
        return self.version

    def set_version(self, version):
        """
        Set the version attribute.

        Parameters:
            version (str): The new version attribute.

        Returns:
            None
        """
        self.version = version

    def get_location(self):
        """
        Get the location attribute.

        Returns:
            str: The location attribute.
        """
        return self.location

    def set_location(self, location):
        """
        Set the location attribute.

        Parameters:
            location (str): The new location attribute.

        Returns:
            None
        """
        self.location = location

    def get_package_manager(self):
        """
        Get the package_manager attribute.

        Returns:
            str: The package_manager attribute.
        """
        return self.package_manager

    def set_package_manager(self, package_manager):
        """
        Set the package_manager attribute.

        Parameters:
            package_manager (str): The new package_manager attribute.

        Returns:
            None
        """
        self.package_manager = package_manager

    def get_language(self):
        """
        Get the language attribute.

        Returns:
            str: The language attribute.
        """
        return self.language

    def set_language(self, language):
        """
        Set the language attribute.

        Parameters:
            language (str): The new language attribute.

        Returns:
            None
        """
        self.language = language

    def get_licenses(self):
        """
        Get the licenses attribute.

        Returns:
            list: The licenses attribute.
        """
        return self.licenses

    def set_licenses(self, licenses):
        """
        Set the licenses attribute.

        Parameters:
            licenses (list): The new licenses attribute.

        Returns:
            None
        """
        self.licenses = licenses

    def get_purl(self):
        """
        Get the purl attribute.

        Returns:
            str: The purl attribute.
        """
        return self.purl

    def set_purl(self, purl):
        """
        Set the purl attribute.

        Parameters:
            purl (str): The new purl attribute.

        Returns:
            None
        """
        self.purl = purl