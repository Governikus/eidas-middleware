/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.dvca.connection.configurator;

import java.io.Console;
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
   * silence PMD
   */
  private Main()
  {

  }

  /**
   * @param args
   */
  public static void main(String[] args)
  {
    log.info("\nThis software will configure your productive eidas-middleware to connect to the D-Trust DVCA.\nRun it in the same folder as your POSeIDAS.xml .\nBACKUP YOUR POSeIDAS.xml BEFOREHAND. ");
    Console c = System.console();
    String con = c.readLine("Continue? (y/N): ");
    if (!"y".equalsIgnoreCase(con))
    {
      System.exit(0);
    }
    PoseidasConfigHandler configHandler = new PoseidasConfigHandler();
    if (!configHandler.loadConfiguration(new File(FileNames.POSEIDAS_XML.getFileName())))
    {
      log.error("Run this jar in the same folder as the POSeIDAS.xml");
      System.exit(-1);
    }
    String clientCertPath = c.readLine("Enter the path to your client certificate:");
    configHandler.initialize(clientCertPath);
    configHandler.updateServiceProviders();
    configHandler.save();
  }
}
