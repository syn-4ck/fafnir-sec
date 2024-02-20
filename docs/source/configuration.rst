
fafnir-sec configuration
========================

.. _configuration:

Set up fafnir-sec with a configuration file
--------------------------------------------

Exclude tools
^^^^^^^^^^^^^^

.. code-block:: yaml

    exclude-tools: # Uncomment the tools you want to exclude from analysis
    - semgrep
    - bandit
    - find-sec-bugs
    - osv-scanner
    #- trivy-sca
    - gitleaks
    - checkov
    - syft

Tools configuration
^^^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

    tools-config:
        semgrep:
            api-key:  # Semgrep API key
        checkov:
            api-key:  #"Add an api key '--bc-api-key <api-key>' to see more detailed insights via https://bridgecrew.cloud"

Container analysis (local image scan)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

    containers:
        image: ""