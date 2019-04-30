FROM governikus/eidas-base-container:1.1.0
MAINTAINER Benny Prange <benny.prange@governikus.de>

# NOTE: Some ENV variables are set in the parent "eidas-base-image"

# Change to the eidas user and directory
USER eidas-middleware
WORKDIR /opt/eidas-middleware

# Download the release from github
RUN wget https://github.com/Governikus/eidas-middleware/releases/download/${VERSION}/configuration-wizard-${VERSION}.jar

RUN    mv configuration-wizard*.jar configuration-wizard.jar &&\
    mkdir -p ${CONFIG_DIR}

ENTRYPOINT ["java", "-jar", "-DconfigDirectory=${CONFIG_DIR}",  "./configuration-wizard.jar"]
