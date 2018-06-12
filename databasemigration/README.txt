=======================================
Database Migration Application
=======================================
Version eumw-1.0.4

Table of contents:
1. Introduction
2. Usage

=======================================
1. This application migrates a h2 database used by the
Governikus eIDAS Middleware from the schema version
1.0.2 to schema version 1.0.3.
This is necessary if the database was created by the
middleware in version 1.0.1 or 1.0.2 and now the
same database should be used by version 1.0.3 or later.

=======================================
2. This application is a Spring Boot Application.
You can run it by executing
java -jar database-migration-1.0.3.jar.
In the working directory there must be folder named config.
In this folder there must exist a file called
application.properties. This file must contain the
following content:

spring.datasource.url=
spring.datasource.username=
spring.datasource.password=
spring.datasource.driver-class-name=org.h2.Driver
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.jpa.hibernate.ddl-auto=update
spring.jpa.hibernate.naming.implicit-strategy=org.hibernate.boot.model.naming.ImplicitNamingStrategyLegacyJpaImpl
spring.jpa.hibernate.naming.physical-strategy=org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl

You must change the first three properties according to
your environment.
You can copy and paste these values from your
application.properties file that is used by the eIDAS
middleware.

Please make a backup of the database by copying the
database file, e.g. eidasm.mv.db, to another place.

Then you can execute the migration with the command
mentioned above. If there were any errors in the
output, send an email to eidas-middleware@governikus.de
with the log output attached.

If the migration was successful, you can start the
middleware in version 1.0.3 or later with the migrated database.
