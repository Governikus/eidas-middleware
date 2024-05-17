FROM governikus/eidas-base-container:${project.version}
MAINTAINER Benny Prange <benny.prange@governikus.de>

ENV WORKING_DIR=/opt/eidas-middleware/database-migration

# Fix the folder permissions because mounting with -v will mount with root
RUN mkdir -p ${WORKING_DIR} &&\
    mkdir -p ${WORKING_DIR}/h2 &&\
    mkdir -p ${WORKING_DIR}/hsql &&\
    chown -R eidas-middleware:eidas-middleware /opt/eidas-middleware

# Change directory
WORKDIR ${WORKING_DIR}

# Copy the freshly built artifact
COPY maven/ ${WORKING_DIR}
RUN mv database-migration*.jar database-migration.jar &&\
    chown eidas-middleware database-migration.jar &&\
    chgrp eidas-middleware database-migration.jar

# Change to the eidas user
USER eidas-middleware

ENTRYPOINT ["java", "-jar", "./database-migration.jar"]
