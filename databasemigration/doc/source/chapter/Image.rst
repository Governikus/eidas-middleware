.. _image:

Migrating using Docker Image
============================

This section describes the migration process for eIDAS Middleware deployments where the Docker Image is used.

Run the Migration Tool
----------------------

The Migration Tool must be configured for the old and new database. In case of the Docker Image, this is done using
volumes and environment variables.

First, you must define the mounts for the old and new database. There are two directories prepared in the Docker Image
to mount the database directories: `/opt/eidas-middleware/database-migration/h2` and
`/opt/eidas-middleware/database-migration/hsql`.

The parameter for mounting a volume in docker is "-v". Here are two examples for different mounting options. Choose
the appropriate option for you local deployment.

To mount an existing named volume, in this example to the h2 directory: ::

    docker run -v <your_named_volume>:/opt/eidas-middleware/database-migration/h2 [...]

To mount a directory from the host machine, in this example to the h2 directory: ::

    docker run -v /path/on/the/host:/opt/eidas-middleware/database-migration/h2 [...]

Secondly, after the mounts for the old and new database are prepared, the configuration for the Migration Tool can be
specified using environment variables. These environment variables must be specified: ::

    H2_DATASOURCE_URL=jdbc:h2:file:/opt/eidas-middleware/database-migration/h2/<database-name>;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
    H2_DATASOURCE_USERNAME=<username>
    H2_DATASOURCE_PASSWORD=<password>
    HSQL_DATASOURCE_URL=jdbc:hsqldb:file:/opt/eidas-middleware/database-migration/hsql/<database-name>
    HSQL_DATASOURCE_USERNAME=<username>
    HSQL_DATASOURCE_PASSWORD=<password>

In case the recommended mount paths are used, only the `database-name`, `username` and `password` for both the old and
the new database must be adapted to your local deployment. If another mount path inside of the container is used, the
path of the `DATASOURCE_URL` must be adapted as well.

This is an example with all necessary parameters to execute the Migration Tool: ::

    docker run --rm \
        -v middleware-h2-database:/opt/eidas-middleware/database-migration/h2 \
        -v middleware-hsql-database:/opt/eidas-middleware/database-migration/hsql \
        -e H2_DATASOURCE_URL=jdbc:h2:file:/opt/eidas-middleware/database-migration/h2/eumw-db;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE \
        -e H2_DATASOURCE_USERNAME=<username> \
        -e H2_DATASOURCE_PASSWORD=<password> \
        -e HSQL_DATASOURCE_URL=jdbc:hsqldb:file:/opt/eidas-middleware/database-migration/hsql/eumw-db; \
        -e HSQL_DATASOURCE_USERNAME=<username> \
        -e HSQL_DATASOURCE_PASSWORD=<password> \
        governikus/eidas-middleware-databasemigration:3.3.0


Before running the Migration Tool, please stop the eIDAS Middleware to prevent data inconsistencies.

The migration tool does not delete or modify data in the old 'H2' database. In case the migration was not successful,
you can start the old eIDAS Middleware again.

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

The values of the HSQL database environment variables of the Migration Tool may be reused for these properties.
In case the same mount point for the volume of the 'HSQL' database is used as during the migration, the same URL can be
used for this deployment. Otherwise, adapt the URL to your local deployment.

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
