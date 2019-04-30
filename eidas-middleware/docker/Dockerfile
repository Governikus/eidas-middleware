FROM governikus/eidas-base-container:1.1.0
MAINTAINER Benny Prange <benny.prange@governikus.de>

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

# Download the release from github
RUN wget https://github.com/Governikus/eidas-middleware/releases/download/${VERSION}/eidas-middleware-${VERSION}.jar

RUN    mv eidas-middleware*.jar eidas-middleware.jar &&\
    mkdir -p ${CONFIG_DIR}

ENTRYPOINT ["java", "-jar", "./eidas-middleware.jar"]
