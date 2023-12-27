/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.configuration.migration.models.poseidas;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;

import jakarta.xml.bind.JAXBException;

import de.governikus.eumw.poseidas.server.idprovider.exceptions.InvalidConfigurationException;
import lombok.NoArgsConstructor;


/**
 * Provides configuration for poseidas. Separate configurations may be needed for project specific business delegates.
 * All "worker" classes in poseidas shall not keep an own copy of the configuration (for instance in serialized form)
 * but re-fetch the configuration object from here if necessary.
 *
 * @author TT
 */
@NoArgsConstructor
public final class PoseidasConfigurator
{

  /**
   * Return the configuration of a given version
   *
   * @return null if there is no such configuration
   */
  public CoreConfigurationDto loadConfig(String pathToConfigFolder)
    throws FileNotFoundException, JAXBException, InvalidConfigurationException
  {
    File configDir = new File(pathToConfigFolder);
    File configfile = new File(configDir, "POSeIDAS.xml");
    return CoreConfigurationDto.readFrom(new FileReader(configfile));
  }
}
