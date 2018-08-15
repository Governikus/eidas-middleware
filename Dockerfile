# Build stage
FROM maven:3.5.4-jdk-8-alpine as build

WORKDIR /eumw
USER root

# Use settings.xml to override maven repos
COPY settings.xml /usr/share/maven/ref/

# Copy pom in first to get dependencies
COPY pom.xml .
COPY configuration-wizard/pom.xml configuration-wizard/pom.xml
COPY databasemigration/pom.xml databasemigration/pom.xml
COPY eid-service/pom.xml eid-service/pom.xml
COPY eidas-common/pom.xml eidas-common/pom.xml
COPY eidas-demo/pom.xml eidas-demo/pom.xml
COPY eidas-middleware/pom.xml eidas-middleware/pom.xml
COPY eidas-starterkit/pom.xml eidas-starterkit/pom.xml
COPY password-generator/pom.xml password-generator/pom.xml
COPY poseidas-configuration/pom.xml poseidas-configuration/pom.xml
COPY poseidas/pom.xml poseidas/pom.xml
COPY utils/pom.xml utils/pom.xml
RUN mvn dependency:go-offline --fail-never

# Copy the rest
COPY . .

# Build
RUN mvn install --projects eidas-middleware --also-make

# Final image
FROM governikus/eidas-base-container:1.0.6

# Define the location of the configuration directory inside of the container
ENV SPRING_CONFIG_ADDITIONAL_LOCATION=file:${CONFIG_DIR}/

# Expose the ports we're interested in
EXPOSE 8443

# Fix the folder permissions because mounting with -v will mount with root
RUN mkdir -p /opt/eidas-middleware/database &&\
    chown eidas-middleware /opt/eidas-middleware/database &&\
    chgrp eidas-middleware /opt/eidas-middleware/database

# Change to the eidas user and directory
USER eidas-middleware
WORKDIR /opt/eidas-middleware

# Copy the jar we built eariler
COPY --from=build /eumw/eidas-middleware/target/eidas-middleware.jar .

RUN mkdir -p ${CONFIG_DIR}

ENTRYPOINT ["java", "-jar", "./eidas-middleware.jar"]
