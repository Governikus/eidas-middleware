Using the configuration migration tool

With eIDAS Middleware version 3.0.0 the configuration of the application is no longer represented by
POSeIDAS.xml and eidasmiddleware.properties but it is stored in the h2 database. To simplify the migration from an older
version of the eIDAS Middleware to the latest version, a tool configuration-migration-3.0.0.jar has been written
which creates a single configuration file from POSeIDAS.xml and eidasmiddleware.properties.
Afterwards, this file is imported in the admin interface.

To use the tool, Java 11 is required and the Java application must be executed with a program argument. As program
argument the path to the directory where POSeIDAS.xml and eidasmiddleware.properties are located must be entered.
Usually POSeIDAS.xml and eidasmiddleware.properties are located in the configuration directory from which the
eidas-middleware.jar is started.

For example, the command to run the tool could look like this:

java -jar configuration-migration.jar /opt/application/config

After running this command, POSeIDAS.xml and eidasmiddleware.properties files will be read and migrated to
the new configuration format. If it is not possible to load POSeIDAS.xml file or eidasmiddleware.properties
file, the configuration migration tool will abort with an error message. In this case please check if the correct
path was passed as parameter.

As a result of the migration, the configuration migration tool creates a new XML file named "middleware-config.xml".
This file is saved in the same folder from which the configuration migration tool was started. If a file with the
same name already exists in this directory, the configuration migration tool terminates with an error message.
Then either change the directory from which the application is to be executed or rename the existing file.

The log of the tool will also show the exact path where the "middleware-config.xml" can be found.

For example:

INFO de.governikus.eumw.configuration.migration.ConfigurationMigrationApplication (ConfigurationMigrationApplication.java:52) -
Migration completed. Eidas middleware configuration file is located in the path /opt/application/configuration-migration/middleware-config.xml

The middleware-config.xml file created by the configuration migration tool can then be uploaded in the admin
interface via "Import/Export Configuration". For more information on how to use the admin interface, please refer
to the official eIDAS Middleware documentation (version 3.0.0 and higher).

Using Docker

If you use eIDAS Middleware in a Docker container, you can run the migration via a Docker container.
You need to mount the directory with the eIDAS middleware configuration as a volume in the container. A script
executes the migration and the middleware-config.xml file will be copied to the eIDAS Middleware configuration
directory.

The command to start the container could look like this:

docker run --rm -v eidas-configuration:/opt/eidas-middleware/configuration governikus/eidas-middleware-configuration-migration:latest

You will see the log output of the migration tool in the console and once the migration is complete, the container
will exit and be removed.


If unexpected errors occur when using the configuration migration tool, you can get further support at
eidas-middleware@governikus.de.
