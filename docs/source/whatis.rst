What is fafnir?
================

``fafnir-sec`` is a free open-source **application security posture management (ASPM)** tool to detect vulnerabilities in the software supply chain.

This tool uses other open-source tools to detect the vulnerabilities related with the application code and build & deploy process.

.. _whatis:

How fafnir works?
------------------

``fafnir-sec`` pulls the official Docker image of the security tools to analyze and detect vulnerabilities.

First of all, ``fafnir-sec`` evaluates the programming languages, technologies and configuration files to choose the needed security tools in the best way. 

Then, ``fafnir-sec`` runs the security tools using official Docker images to detect all vulnerabilities from SAST, SCA, container analysis, secrets, IaC...

Finally, the goal of ``fafnir-sec`` is group all vulnerabilities and report it in a standard and single way.
