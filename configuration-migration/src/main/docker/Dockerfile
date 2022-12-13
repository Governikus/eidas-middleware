FROM governikus/eidas-base-container:${project.version}
MAINTAINER Benny Prange <benny.prange@governikus.de>

# Fix the folder permissions because mounting with -v will mount with root
RUN mkdir -p /opt/eidas-middleware/configuration-migration &&\
    chown eidas-middleware /opt/eidas-middleware/configuration-migration &&\
    chgrp eidas-middleware /opt/eidas-middleware/configuration-migration

COPY --chown=eidas-middleware:eidas-middleware run-migration.sh /opt/eidas-middleware/configuration-migration

# Copy the freshly built artifact
COPY maven/ /opt/eidas-middleware/configuration-migration

WORKDIR /opt/eidas-middleware/configuration-migration

RUN mv configuration-migration*.jar configuration-migration.jar

RUN chown eidas-middleware configuration-migration.jar &&\
    chgrp eidas-middleware configuration-migration.jar &&\
    chmod u+x run-migration.sh

# Change to the eidas user and directory
USER eidas-middleware
WORKDIR /opt/eidas-middleware/configuration-migration

ENTRYPOINT /opt/eidas-middleware/configuration-migration/run-migration.sh
