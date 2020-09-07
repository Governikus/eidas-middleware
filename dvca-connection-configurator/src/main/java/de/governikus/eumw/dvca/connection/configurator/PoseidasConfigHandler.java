/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.dvca.connection.configurator;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.apache.commons.io.IOUtils;

import de.governikus.eumw.dvca.connection.configurator.identifier.FileNames;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


/**
 * This class loads, changes and saves the POSeIDAS configuration.
 *
 * @author muenchow
 */
@Slf4j
class PoseidasConfigHandler
{

  /**
   * this will hold all values for the POSeIDAS core configuration
   */
  private PoseidasCoreConfiguration coreConfig;

  /**
   * CSCA root certificate
   */
  private byte[] cscaRootCertificate;

  /**
   * loads the configuration from a file
   *
   * @param poseidasXml the configuration file that should hold the configuration
   */
  boolean loadConfiguration(final File poseidasXml)
  {
    try
    {
      cscaRootCertificate = IOUtils.resourceToByteArray("/csca-germany_05-2019_self_signed.cer");
    }
    catch (IOException e)
    {
      log.error("Cannot load the CSCA root certificate", e);
      return false;
    }

    if (!poseidasXml.exists())
    {
      log.error("No POSeIDAS.xml file found at '{}'. Make sure that the POSeIDAS.xml is in your current working directory.",
                poseidasXml);
      return false;
    }
    log.trace("Loading configuration from POSeIDAS.xml file: {}", poseidasXml);
    coreConfig = XmlHelper.unmarshal(poseidasXml, PoseidasCoreConfiguration.class);
    return true;
  }

  /**
   * Updates the master and defect list trust anchors with the new CSCA root certificate.
   */
  void updateServiceProviders()
  {
    List<ServiceProviderType> serviceProvider = coreConfig.getServiceProvider();
    for ( ServiceProviderType serviceProviderType : serviceProvider )
    {
      PkiConnectorConfigurationType pkiConnectorConfiguration = serviceProviderType.getEPAConnectorConfiguration()
                                                                                   .getPkiConnectorConfiguration();

      pkiConnectorConfiguration.setMasterListTrustAnchor(cscaRootCertificate);
    }
  }

  /**
   * Saves the changes to POSeIDAS.xml file.
   */
  void save()
  {
    XmlHelper.marshalObjectToFile(coreConfig, "./" + FileNames.POSEIDAS_XML.getFileName());
    log.info("Done!");
  }

}
