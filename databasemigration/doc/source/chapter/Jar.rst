.. _jar:

Migrating using the JAR file
============================

This section describes the migration process for eIDAS Middleware deployments where the JAR is directly used, e.g.
when you are using the OVA image or you have deployed the eIDAS Middleware on any virtual machine.

Setup the applications.properties
---------------------------------

The Migration Tool must be configured for the old and new database. Please see the following example, which must be
adapted to your local deployment:

.. literalinclude:: application.properties

This file should be created in the working directory of the Migration Tool, typically in the same directory as the
Migration Tool JAR file.

The values for the 'H2' database can be copied from the `application.properties` of your eIDAS Middleware deployment,
the property names however are slightly different in the Migration Tool.
We suggest to define a new directory for the 'HSQL' database. The directory should be empty and will be created if
necessary.

Run the Migration Tool
----------------------

Before running the Migration Tool, please stop the eIDAS Middleware to prevent data inconsistencies.

The migration tool does not delete or modify data in the old 'H2' database. In case the migration was not successful,
you can start the old eIDAS Middleware again.

To run the Migration Tool, execute the following command from the directory where the Migration Tool JAR file is stored.
Please make sure that the application.properties for the Migration Tool is stored in the same directory.

::

    java -jar database-migration-3.3.0.jar

The tool should exit without errors. In case the tool did encounter a problem and did not exit cleanly, please
contact the eIDAS Middleware support at Governikus with the log from the Migration Tool.

Prepare and start the eIDAS Middleware Configuration
----------------------------------------------------

The database configuration of the eIDAS Middleware must be updated to use the new 'HSQL' database. Therefore, make the
following changes in the `application.properties` of the eIDAS Middleware: ::

    # Old H2 database configuration which should be deleted:
    spring.datasource.url=jdbc:h2:file:/path/to/your/h2-database;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
    spring.datasource.username=<username>
    spring.datasource.password=<password>

    # The new HSQL database configuration:
    spring.datasource.url=jdbc:hsqldb:file:/path/to/your/hsql-database
    spring.datasource.username=<username>
    spring.datasource.password=<password>

The values for the HSQL database can be copied from the `application.properties` of the Migration Tool.

Afterwards, you can start the eIDAS Middleware application.

With version 3.3.0 of the eIDAS Middleware, a newer API version of the DVCA interface is used. This version is available
at different endpoints, which means that the DVCA configuration must be updated for the new version.

For eIDAS Middlewares in test environments: ::

    Terminal Authentication service URL
    Old: https://dvca-r1.governikus-eid.de/gov_dvca/ta-service
    New: https://dvca-r1.governikus-eid.de/gov_dvca/ta-service-140

    Passive Authentication service URL
    Old: https://dvca-r1.governikus-eid.de/gov_dvca/pa-service
    New: https://dvca-r1.governikus-eid.de/gov_dvca/pa-service-140

For eIDAS Middlewares in productive environments: ::

    Terminal Authentication service URL
    Old: https://berca-p1.d-trust.net/ps/dvca-at/v1_1
    New: https://berca-p1.d-trust.net/ps/dvca-at/v1_4

    Passive Authentication service URL
    Old: https://berca-p1.d-trust.net/ps/scs/v1_1
    New: https://berca-p1.d-trust.net/ps/scs/v1_4

After this change, the connection to the DVCA should be working again, which can be verified by manually renewing
the CVC and renewing the Master and Defect List.
