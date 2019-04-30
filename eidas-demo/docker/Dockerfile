FROM governikus/eidas-base-container:1.1.0
MAINTAINER Benny Prange <benny.prange@governikus.de>

# NOTE: Some ENV variables are set in the parent "eidas-base-image"

# Change to the eidas user and directory
USER eidas-middleware
WORKDIR /opt/eidas-middleware

# Create the config directory
RUN mkdir /opt/eidas-middleware/config

# Download the release from github
RUN wget https://github.com/Governikus/eidas-middleware/releases/download/${VERSION}/eidas-demo-${VERSION}.jar

RUN    mv eidas-demo*.jar eidas-demo.jar &&\
    mkdir -p ${CONFIG_DIR}

ENTRYPOINT ["java", "-jar", "./eidas-demo.jar"]
