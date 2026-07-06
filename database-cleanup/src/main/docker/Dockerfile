FROM ${BASE_IMAGE_TO_USE}
MAINTAINER Michael Ciwinski <michael.ciwinski@governikus.de>

ENV WORKING_DIR=/opt/eidas-middleware

# Fix the folder permissions because mounting with -v will mount with root
RUN mkdir -p ${WORKING_DIR} &&\
    mkdir -p ${WORKING_DIR}/database &&\
    chown -R eidas-middleware:eidas-middleware ${WORKING_DIR}

# Change directory
WORKDIR ${WORKING_DIR}

# Copy the freshly built artifact
COPY database-cleanup/target/database-cleanup.jar ${WORKING_DIR}/database-cleanup.jar

RUN chown eidas-middleware database-cleanup.jar
RUN chgrp eidas-middleware database-cleanup.jar

# Change to the eidas user
USER eidas-middleware

ENTRYPOINT ["java", "-jar", "./database-cleanup.jar"]
