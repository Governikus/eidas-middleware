====================================
Overview
====================================
In version 3.3.0 of the eIDAS Middleware, the used database changes from 'H2' to 'HSQL'.
A migration tool is provided to migrate the data from an old 'H2' database to a new 'HSQL' database.

There are two options for the usage of the Migration Tool, depending on the type of deployment of your eIDAS Middleware.

#. Executable JAR file for JAR deployments of the eIDAS Middleware
#. Docker Image for Docker deployments of the eIDAS Middleware

The following documentation will provide guidance for both options.

The migration is tested and supported for versions 3.0.x, 3.1.x and 3.2.x to 3.3.0. Older versions are not officially
supported.

:ref:`jar` describes the migration with the Executable JAR file, while :ref:`image` describes the Docker Image
migration.
