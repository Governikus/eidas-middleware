#!/bin/sh

FILE=middleware-config.xml

echo "--- Starting script ---"
java -jar configuration-migration.jar /opt/eidas-middleware/configuration

if test -f "$FILE"; then
  echo "--- Copy $FILE  to ${CONFIG_DIR} ---"
  chown eidas-middleware "$FILE" &&\
  chgrp eidas-middleware "$FILE"
  cp middleware-config.xml ${CONFIG_DIR}
  echo "-- Configuration migration finished. ---"
else
  echo "--- $FILE does not exist. Migration was not successful. Please see log for more information. ---"
fi
echo "--- Script finished ---"
