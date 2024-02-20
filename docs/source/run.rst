Run fafnir-sec
==============

.. _run:

Run fafnir-sec for first time
------------------------------

You can run the tool in a easy way using the following command:

.. code-block:: console

   fafnir $PATH_TO_CODE

.. _options:

Options
--------

+----------------+----------------------+---------------------------------+
| Option name    | Flag                 | Description                     |
|                |                      |                                 |
+================+======================+=================================+
| Verbose        | -v, --verbose        | Verbose mode (debug mode)       |
+----------------+----------------------+---------------------------------+
| Configuration  | -c, --configuration  | Set up fafnir-sec configuration |
|                |                      | using the configuration file    |
+----------------+----------------------+---------------------------------+
| Asynchronous   | -a, --asynchronous   | Asynchronous mode to run        |
|                |                      | security tools at the same time |
+----------------+----------------------+---------------------------------+
| Output type    | -t, --output-type    | Report type: json, sarif        |
|                |                      |                                 |
+----------------+----------------------+---------------------------------+
| Output path    | -t, --output-path    | Path to the fafnir-sec report   |
|                |                      |                                 |
+----------------+----------------------+---------------------------------+
| Disable API    | -x, --disable-apis   | Disable API requests            |
|                |                      |                                 |
+----------------+----------------------+---------------------------------+
