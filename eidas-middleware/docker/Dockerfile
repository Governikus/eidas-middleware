FROM governikus/eidas-base-container:1.0.6
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

# Re-download zulu-openjdk to obtain jarsigner
ENV ZULU_ARCH=zulu8.30.0.1-jdk8.0.172-linux_x64
RUN wget http://cdn.azul.com/zulu/bin/${ZULU_ARCH}.tar.gz -O /tmp/${ZULU_ARCH}.tar.gz \
    && tar xf /tmp/${ZULU_ARCH}.tar.gz -C /tmp

# Download and verify the release from github
RUN wget https://github.com/Governikus/eidas-middleware/releases/download/${VERSION}/eidas-middleware-${VERSION}.jar \
    && /tmp/${ZULU_ARCH}/bin/jarsigner -verify -strict -verbose -certs eidas-middleware-${VERSION}.jar \
    && mv eidas-middleware-${VERSION}.jar eidas-middleware.jar \
    && mkdir -p ${CONFIG_DIR}

# Cleanup
RUN rm -fr /tmp/${ZULU_ARCH}*

ENTRYPOINT ["java", "-jar", "./eidas-middleware.jar"]
