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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.IOUtils;

import de.governikus.eumw.dvca.connection.configurator.identifier.FileNames;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


/**
 * This class loads, changes and saves the POSeIDAS configuration.
 *
 * @author muenchow
 */
@Slf4j
public class PoseidasConfigHandler
{

  /**
   * this will hold all values for the POSeIDAS core configuration
   */
  private PoseidasCoreConfiguration coreConfig;

  /**
   * Blacklist trustanchor certificate
   */
  private byte[] blackListCert;

  /**
   * DVCA SSL certificate
   */
  private byte[] dvcaCert;

  /**
   * Client SSL certificate
   */
  private X509Certificate clientCert;


  /**
   * loads the configuration from a file
   *
   * @param poseidasXml the configuration file that should hold the configuration
   */
  public boolean loadConfiguration(final File poseidasXml)
  {
    if (!poseidasXml.exists())
    {
      log.debug("no POSeIDAS.xml file found at '{}'", poseidasXml);
      return false;
    }
    log.trace("loading configuration from POSeIDAS.xml file: {}", poseidasXml);
    coreConfig = XmlHelper.unmarshal(poseidasXml, PoseidasCoreConfiguration.class);
    return true;
  }


  /**
   * Prepare certificates.
   *
   * @throws IOException
   */
  public void initialize(String clientCertPath)// String keyStorePath, String password, String alias)
  {
    try
    {
      blackListCert = IOUtils.toByteArray(PoseidasConfigHandler.class.getClassLoader()
                                                                     .getResourceAsStream("blacklist_prod.der"));
    }
    catch (IOException e)
    {
      log.error("Could not read blacklist certificate.\n{}", e.getMessage());
    }
    try
    {
      dvcaCert = IOUtils.toByteArray(PoseidasConfigHandler.class.getClassLoader()
                                                                .getResourceAsStream("berca-p1.der.der"));
    }
    catch (IOException e)
    {
      log.error("Could not read dvca server certificate.\n{}", e.getMessage());
    }
    InputStream clientCertInputStream;
    try
    {
      clientCertInputStream = new FileInputStream(new File(clientCertPath));
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      clientCert = (X509Certificate)certFactory.generateCertificate(clientCertInputStream);
    }
    catch (IOException | CertificateException e)
    {
      log.error("Client certificate corrupted or missing.\n{}", e.getMessage());
    }

  }

  /**
   * Updates all service providers by exchanging URIs, SSL certificates and blacklist trust anchor
   * certificates.
   */
  public void updateServiceProviders()
  {
    List<ServiceProviderType> serviceProvider = coreConfig.getServiceProvider();
    for ( ServiceProviderType serviceProviderType : serviceProvider )
    {
      PkiConnectorConfigurationType pkiConnectorConfiguration = serviceProviderType.getEPAConnectorConfiguration()
                                                                                   .getPkiConnectorConfiguration();
      pkiConnectorConfiguration.getTerminalAuthService().setUrl("https://berca-p1.d-trust.net/ps/dvca-at");
      pkiConnectorConfiguration.getRestrictedIdService().setUrl("https://berca-p1.d-trust.net/ps/dvsd_v2");
      pkiConnectorConfiguration.getPassiveAuthService().setUrl("https://berca-p1.d-trust.net/ps/scs");
      pkiConnectorConfiguration.getDvcaCertDescriptionService()
                               .setUrl("https://berca-p1.d-trust.net/ps/dvca-at-cert-desc");

      pkiConnectorConfiguration.setBlackListTrustAnchor(blackListCert);
      Iterator<SslKeysType> iterator = pkiConnectorConfiguration.getSslKeys().iterator();
      while (iterator.hasNext())
      {
        SslKeysType sslKeysType = (SslKeysType)iterator.next();
        sslKeysType.setServerCertificate(dvcaCert);
        sslKeysType.getClientCertificate().clear();
        try
        {
          sslKeysType.getClientCertificate().add(clientCert.getEncoded());
        }
        catch (CertificateEncodingException e)
        {
          log.error("Client certificate can't be encoded.\n{}", e.getMessage());
        }
      }
    }
  }

  /**
   * Saves the changes to POSeIDAS.xml file.
   */
  public void save()
  {
    XmlHelper.marshalObjectToFile(coreConfig, "./" + FileNames.POSEIDAS_XML.getFileName());
    log.info("Done!");
  }

}
