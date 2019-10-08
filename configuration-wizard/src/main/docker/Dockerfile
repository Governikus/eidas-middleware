FROM governikus/eidas-base-container:${project.version}
MAINTAINER Benny Prange <benny.prange@governikus.de>

# NOTE: Some ENV variables are set in the parent "eidas-base-image"

# Change to the eidas user and directory
USER eidas-middleware
WORKDIR /opt/eidas-middleware

# Copy the freshly built artifact
COPY maven/ /opt/eidas-middleware

RUN    mv configuration-wizard*.jar configuration-wizard.jar &&\
    mkdir -p ${CONFIG_DIR}

ENTRYPOINT ["java", "-jar", "-DconfigDirectory=${CONFIG_DIR}",  "./configuration-wizard.jar"]
