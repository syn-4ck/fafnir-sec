Getting started
===============

.. _installation:

Installation
------------

**fafnir** can be executed in Linux, MacOS and Windows OS. To use ``fafnir``, you can install it using two ways: docker or python.

Docker:
^^^^^^^

**Requirements**:

* Docker installed
* Internet access in the machine to pull the image from Docker Hub

.. code-block:: console

   docker pull ghsyn4ck/fafnir:latest


Python:
^^^^^^^

**Requirements**:

* Python 3.6 or later installed
* Pip installed
* Internet access in the machine to install ``fafnir`` module and the dependencies from Pypi.

.. code-block:: console

   pip install fafnir

.. _usage:

Usage
-----

.. warning::
    It is required to have an Internet access to pull Docker images from the tools

You can run the ``--help`` option to see all options to run the tool:

Docker:
^^^^^^^

Run the container previously pulled with the command to execute:

.. code-block:: console

   docker run ghsyn4ck/fafnir:latest fafnir --help


Python:
^^^^^^^

Run the CLI installed from Pypi using the correct options:

.. code-block:: console

   fafnir --help
