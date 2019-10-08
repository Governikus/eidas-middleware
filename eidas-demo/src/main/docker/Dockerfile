FROM governikus/eidas-base-container:${project.version}
MAINTAINER Benny Prange <benny.prange@governikus.de>

# NOTE: Some ENV variables are set in the parent "eidas-base-image"

# Change to the eidas user and directory
USER eidas-middleware
WORKDIR /opt/eidas-middleware

# Create the config directory
RUN mkdir /opt/eidas-middleware/config

# Copy the freshly built artifact
COPY maven/ /opt/eidas-middleware

RUN    mv eidas-demo*.jar eidas-demo.jar &&\
    mkdir -p ${CONFIG_DIR}

ENTRYPOINT ["java", "-jar", "./eidas-demo.jar"]
