/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.dvca.connection.configurator;

import java.io.File;

import de.governikus.eumw.dvca.connection.configurator.identifier.FileNames;
import lombok.extern.slf4j.Slf4j;


/**
 * @author muenchow
 */
@Slf4j
public final class Main
{

  /**
   * @param args
   */
  public static void main(String[] args)
  {
    log.info("#####");
    log.info("This software will update the DVCA configuration of your TEST eidas-middleware to use the new test DVCA with request signer support.");
    log.info("A backup will be created.");
    log.info("#####");

    PoseidasConfigHandler configHandler = new PoseidasConfigHandler();
    log.info("Starting the update process:");
    if (!configHandler.loadCertificates())
    {
      log.error("Cannot load the certificates, aborting.");
      System.exit(-1);
    }

    if (!configHandler.loadConfiguration(new File(FileNames.POSEIDAS_XML.getFileName())))
    {
      log.error("There was an error during the execution, aborting.");
      System.exit(-1);
    }

    if (!configHandler.backUp(new File(FileNames.POSEIDAS_XML.getFileName())))
    {
      log.error("Cannot create the backup of the configuration, aborting.");
      System.exit(-1);
    }

    if (!configHandler.updateServiceProviders())
    {
      log.error("Cannot update the configuration, aborting.");
      System.exit(-1);
    }
    if (!configHandler.save())
    {
      log.error("Cannot save the modified configuration, aborting.");
      System.exit(-1);
    }
    log.info("Successfully updated the POSeIDAS.xml.");
  }
}
