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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
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
   * CSCA test root certificate
   */
  private byte[] cscaRootCertificate;

  /**
   * Black list signer issuer certificate
   */
  private byte[] blackListIssuerCertificate;

  /**
   * DVCA TLS certificate
   */
  private byte[] dvcaTlsCertificate;

  /**
   * Load the certificates from the classpath
   *
   * @return True when loading was successful, false otherwise
   */
  boolean loadCertificates()
  {
    try
    {
      cscaRootCertificate = IOUtils.resourceToByteArray("/DE_TEST_CSCA0006.cer");
      blackListIssuerCertificate = IOUtils.resourceToByteArray("/Governikus_CA_12_PN_Governikus_Root_CA_4_PN_.cer");
      dvcaTlsCertificate = IOUtils.resourceToByteArray("/dvca-r1.governikus-eid.de.cer");
      return true;
    }
    catch (IOException e)
    {
      log.error("Cannot load certificates", e);
      return false;
    }
  }

  /**
   * loads the configuration from a file
   *
   * @param poseidasXml the configuration file that should hold the configuration
   * @return true when the configuration could be loaded, false otherwise
   */
  boolean loadConfiguration(final File poseidasXml)
  {
    if (!poseidasXml.exists())
    {
      log.error("No POSeIDAS.xml file found. Make sure that the POSeIDAS.xml is in your current working directory.");
      return false;
    }
    log.trace("Loading configuration from POSeIDAS.xml file: {}", poseidasXml);
    coreConfig = XmlHelper.unmarshal(poseidasXml, PoseidasCoreConfiguration.class);
    return true;
  }

  /**
   * Updates the master and defect list trust anchors with the new CSCA root certificate.
   */
  boolean updateServiceProviders()
  {
    List<ServiceProviderType> serviceProvider = coreConfig.getServiceProvider();
    for ( ServiceProviderType serviceProviderType : serviceProvider )
    {
      if (!"govDvca".equalsIgnoreCase(serviceProviderType.getEPAConnectorConfiguration()
                                                         .getPkiConnectorConfiguration()
                                                         .getPolicyImplementationId()))
      {
        log.error("ServiceProvider with entityID {} is configured for the productive DVCA, aborting.",
                  serviceProviderType.getEntityID());
        return false;
      }
      PkiConnectorConfigurationType pkiConnectorConfiguration = serviceProviderType.getEPAConnectorConfiguration()
                                                                                   .getPkiConnectorConfiguration();

      pkiConnectorConfiguration.setMasterListTrustAnchor(cscaRootCertificate);
      pkiConnectorConfiguration.setBlackListTrustAnchor(blackListIssuerCertificate);
      pkiConnectorConfiguration.getSslKeys()
                               .forEach(sslKeysType -> sslKeysType.setServerCertificate(dvcaTlsCertificate));
      pkiConnectorConfiguration.getTerminalAuthService()
                               .setUrl("https://dvca-r1.governikus-eid.de/gov_dvca/ta-service");
      pkiConnectorConfiguration.getRestrictedIdService()
                               .setUrl("https://dvca-r1.governikus-eid.de/gov_dvca/ri-service");
      pkiConnectorConfiguration.getPassiveAuthService()
                               .setUrl("https://dvca-r1.governikus-eid.de/gov_dvca/pa-service");
      pkiConnectorConfiguration.getDvcaCertDescriptionService()
                               .setUrl("https://dvca-r1.governikus-eid.de/gov_dvca/certDesc-service");
    }
    return true;
  }

  boolean backUp(final File poseidasXml)
  {
    try
    {
      if (Paths.get(FileNames.POSEIDAS_XML.getFileName() + ".backup").toFile().exists())
      {
        log.warn("Removing previous backup");
        Files.delete(Paths.get(FileNames.POSEIDAS_XML.getFileName() + ".backup"));
      }
      Files.copy(poseidasXml.toPath(),
                 poseidasXml.toPath().resolveSibling(FileNames.POSEIDAS_XML.getFileName() + ".backup"));
      return true;
    }
    catch (IOException e)
    {
      log.error("Cannot create backup for POSeIDAS.xml", e);
      return false;
    }
  }

  /**
   * Saves the changes to POSeIDAS.xml file.
   */
  boolean save()
  {
    try
    {
      XmlHelper.marshalObjectToFile(coreConfig, "./" + FileNames.POSEIDAS_XML.getFileName());
      return true;
    }
    catch (Exception e)
    {
      log.error("Cannot save the modified configuration, e");
      return false;
    }
  }

}
