/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model.poseidasxml;

import java.io.File;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.web.model.AbstractConfigFileTest;
import de.governikus.eumw.configuration.wizard.web.model.CertificateForm;
import de.governikus.eumw.poseidas.config.schema.EPAConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


/**
 * author Pascal Knueppel <br>
 * created at: 06.04.2018 - 07:52 <br>
 * <br>
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class PoseidasCoreConfigFormTest extends AbstractConfigFileTest
{

  /**
   * will return the fully quallified URL to the poseidas xml based on the given configuration directory in
   * the test-resources
   *
   * @param configDir the configuration directory that holds the test-resources
   * @return the URL to the xml file
   */
  private URL getPoseidasXmlFilePath(String configDir)
  {
    final String propertiesPath = CONFIGURATION_LOCATION + SLASH + configDir + SLASH
                                  + FileNames.POSEIDAS_XML.getFileName();
    URL propertiesUrl = getClass().getResource(propertiesPath);
    Assertions.assertNotNull(propertiesUrl,
                             FileNames.POSEIDAS_XML.getFileName() + " could not be found in " + "path '"
                                            + propertiesPath + "'");
    return propertiesUrl;
  }

  /**
   * will try to get the given POSEiDAS.xml and unmarshal it into a POJO
   *
   * @param poseidasXmlUrl the url to the poseidas.xml file
   * @return the unmarshalled POJO
   */
  public static PoseidasCoreConfiguration getPoseidasCoreConfiguration(URL poseidasXmlUrl)
  {
    return XmlHelper.unmarshal(new File(poseidasXmlUrl.getFile()), PoseidasCoreConfiguration.class);
  }

  /**
   * will read the POSeIDAS.xml from the resources and will assert that the values are read correctly
   */
  @Test
  public void testReadPoseidasXmlConfiguration()
  {
    URL poseidasXmlUrl = getPoseidasXmlFilePath(CONFIG_DIR_SUCCESS);
    PoseidasCoreConfiguration poseidasCoreConfiguration = getPoseidasCoreConfiguration(poseidasXmlUrl);
    PoseidasCoreConfigForm poseidasCoreConfigForm = new PoseidasCoreConfigForm();
    poseidasCoreConfigForm.loadConfiguration(new File(poseidasXmlUrl.getFile()));

    final String serverUrl = "https://myhost:8443/eidas-middleware";
    EQUAL_NULL_CHECK.accept(serverUrl, poseidasCoreConfiguration.getServerUrl());
    EQUAL_NULL_CHECK.accept(poseidasCoreConfiguration.getServerUrl().trim(),
                            poseidasCoreConfigForm.getCoreConfig().getServerUrl());

    final int maxPendingRequests = 500;
    Assertions.assertEquals(maxPendingRequests, poseidasCoreConfiguration.getSessionMaxPendingRequests());

    checkTimerConfigurationForConfigDir1(poseidasCoreConfiguration, poseidasCoreConfigForm);

    Assertions.assertTrue(poseidasCoreConfigForm.getServiceProviders().size() == 1);
    Assertions.assertNotNull(poseidasCoreConfigForm.getServiceProviders().get(0));
    Assertions.assertEquals(1, poseidasCoreConfiguration.getServiceProvider().size());
    checkThatServiceProviderTypesAreEqualForConfigDir1(poseidasCoreConfiguration.getServiceProvider().get(0),
                                                       poseidasCoreConfigForm.getServiceProviders().get(0));
  }

  /**
   * checks that the given types are not null and equal in their values
   */
  private void checkThatServiceProviderTypesAreEqualForConfigDir1(ServiceProviderType serviceProviderType1,
                                                                  ServiceProviderForm serviceProviderForm)
  {
    Assertions.assertNotNull(serviceProviderForm);
    ServiceProviderType serviceProviderType2 = serviceProviderForm.getServiceProvider();
    Assertions.assertNotNull(serviceProviderType1);
    Assertions.assertNotNull(serviceProviderType2);
    final String entityId = "providerA";
    EQUAL_NULL_CHECK.accept(entityId, serviceProviderType1.getEntityID());
    EQUAL_NULL_CHECK.accept(serviceProviderType1.getEntityID(), serviceProviderType2.getEntityID());
    EQUAL_NULL_CHECK.accept(serviceProviderType2.getEntityID(), serviceProviderForm.getEntityID());

    EPAConnectorConfigurationType epaConnectorConfiguration1 = serviceProviderType1.getEPAConnectorConfiguration();
    EPAConnectorConfigurationType epaConnectorConfiguration2 = serviceProviderType2.getEPAConnectorConfiguration();
    Assertions.assertNotNull(epaConnectorConfiguration1);
    Assertions.assertNotNull(epaConnectorConfiguration2);
    Assertions.assertEquals(epaConnectorConfiguration1.isUpdateCVC(),
                            epaConnectorConfiguration2.isUpdateCVC());
    final String cvcRefId = "provider_a";
    EQUAL_NULL_CHECK.accept(cvcRefId, epaConnectorConfiguration2.getCVCRefID());
    EQUAL_NULL_CHECK.accept(epaConnectorConfiguration1.getCVCRefID(),
                            epaConnectorConfiguration2.getCVCRefID());
    final String paosReceiverUrl = "https://myhost:8443/eidas-middleware/paosreceiver";
    EQUAL_NULL_CHECK.accept(paosReceiverUrl, epaConnectorConfiguration2.getPaosReceiverURL());
    EQUAL_NULL_CHECK.accept(epaConnectorConfiguration1.getPaosReceiverURL(),
                            epaConnectorConfiguration2.getPaosReceiverURL());
    final Integer hoursRefreshCvcBeforeExpiration = 48;
    Assertions.assertEquals(hoursRefreshCvcBeforeExpiration,
                            epaConnectorConfiguration2.getHoursRefreshCVCBeforeExpires());
    Assertions.assertEquals(epaConnectorConfiguration1.getHoursRefreshCVCBeforeExpires(),
                            epaConnectorConfiguration2.getHoursRefreshCVCBeforeExpires());

    PkiConnectorConfigurationType pkiConnectorConfiguration1 = epaConnectorConfiguration1.getPkiConnectorConfiguration();
    checkThatPkiConnectorConfigurationsAreEqual(pkiConnectorConfiguration1, serviceProviderForm);
  }

  /**
   * will check that the values of the pki connector configurations are equals within the
   * service-provider-form object and the unmarshalled object
   *
   * @param pkiConnectorConfiguration1 the unmarshalled object from the xml
   * @param serviceProviderForm service provider form object that is displayed in the html view
   */
  private void checkThatPkiConnectorConfigurationsAreEqual(PkiConnectorConfigurationType pkiConnectorConfiguration1,
                                                           ServiceProviderForm serviceProviderForm)
  {
    PkiConnectorConfigurationType pkiConnectorConfiguration2 = serviceProviderForm.getServiceProvider()
                                                                                  .getEPAConnectorConfiguration()
                                                                                  .getPkiConnectorConfiguration();
    Assertions.assertNotNull(pkiConnectorConfiguration1);
    Assertions.assertNotNull(pkiConnectorConfiguration2);

    final String policyImplementationId = "govDvca";
    EQUAL_NULL_CHECK.accept(policyImplementationId, pkiConnectorConfiguration1.getPolicyImplementationId());
    EQUAL_NULL_CHECK.accept(pkiConnectorConfiguration1.getPolicyImplementationId(),
                            pkiConnectorConfiguration2.getPolicyImplementationId());
    EQUAL_NULL_CHECK.accept(pkiConnectorConfiguration1.getPolicyImplementationId(),
                            serviceProviderForm.getPolicyID().getValue());

    checkPkiServiceTypeEquality(pkiConnectorConfiguration1.getTerminalAuthService(),
                                pkiConnectorConfiguration2.getTerminalAuthService());
    checkPkiServiceTypeEquality(pkiConnectorConfiguration1.getRestrictedIdService(),
                                pkiConnectorConfiguration2.getRestrictedIdService());
    checkPkiServiceTypeEquality(pkiConnectorConfiguration1.getPassiveAuthService(),
                                pkiConnectorConfiguration2.getPassiveAuthService());
    checkPkiServiceTypeEquality(pkiConnectorConfiguration1.getDvcaCertDescriptionService(),
                                pkiConnectorConfiguration2.getDvcaCertDescriptionService());

    checkCertificateAnchor(pkiConnectorConfiguration1.getBlackListTrustAnchor(),
                           pkiConnectorConfiguration2.getBlackListTrustAnchor(),
                           serviceProviderForm.getBlackListTrustAnchor());

    checkCertificateAnchor(pkiConnectorConfiguration1.getDefectListTrustAnchor(),
                           pkiConnectorConfiguration2.getDefectListTrustAnchor(),
                           serviceProviderForm.getDefectListTrustAnchor());

    checkCertificateAnchor(pkiConnectorConfiguration1.getMasterListTrustAnchor(),
                           pkiConnectorConfiguration2.getMasterListTrustAnchor(),
                           serviceProviderForm.getMasterListTrustAnchor());

    Assertions.assertEquals(1, pkiConnectorConfiguration1.getSslKeys().size());
    Assertions.assertEquals(1, pkiConnectorConfiguration2.getSslKeys().size());
    checkSslKeysForEquality(pkiConnectorConfiguration1.getSslKeys().get(0),
                            pkiConnectorConfiguration2.getSslKeys().get(0),
                            serviceProviderForm.getSslKeysForm());
  }

  /**
   * will check that the given ssl key values are matching
   */
  private void checkSslKeysForEquality(SslKeysType sslKeys1, SslKeysType sslKeys2, SslKeysForm sslKeysForm)
  {
    Assertions.assertNotNull(sslKeys1);
    Assertions.assertNotNull(sslKeys2);
    Assertions.assertNotNull(sslKeysForm);

    Assertions.assertEquals(sslKeys1.getId(), sslKeys2.getId());

    Assertions.assertArrayEquals(sslKeys1.getClientKey(), sslKeys2.getClientKey());
    Assertions.assertArrayEquals(sslKeys2.getClientKey(),
                                 sslKeysForm.getClientKeyForm().getPrivateKey().getEncoded());

    Assertions.assertArrayEquals(sslKeys1.getServerCertificate(), sslKeys2.getServerCertificate());
    Assertions.assertArrayEquals(sslKeys2.getServerCertificate(),
                                 getCertificateBytes(sslKeysForm.getServerCertificate().getCertificate()));

    Assertions.assertNotNull(sslKeys1.getClientCertificate());
    Assertions.assertNotNull(sslKeys2.getClientCertificate());
    Assertions.assertEquals(1, sslKeys1.getClientCertificate().size());
    Assertions.assertEquals(1, sslKeys2.getClientCertificate().size());
    Assertions.assertArrayEquals(sslKeys1.getClientCertificate().get(0),
                                 sslKeys2.getClientCertificate().get(0));
    Assertions.assertArrayEquals(sslKeys2.getClientCertificate().get(0),
                                 getCertificateBytes(sslKeysForm.getClientKeyForm().getX509Certificate()));
  }

  /**
   * will check that the values of the given types are equal
   */
  private void checkPkiServiceTypeEquality(PkiServiceType pkiServiceType1, PkiServiceType pkiServiceType2)
  {
    Assertions.assertNotNull(pkiServiceType1);
    Assertions.assertNotNull(pkiServiceType2);
    EQUAL_NULL_CHECK.accept(pkiServiceType1.getUrl(), pkiServiceType2.getUrl());
    EQUAL_NULL_CHECK.accept(pkiServiceType1.getSslKeysId(), pkiServiceType2.getSslKeysId());
  }

  /**
   * will check that the parameters do all have the same values
   *
   * @param anchor1 a trust anchor from the poseidas xml
   * @param anchor2 a trust anchor from the poseidas xml
   * @param certificateForm a trust anchor from the poseidas xml that was translated into a
   *          {@link CertificateForm} object
   */
  private void checkCertificateAnchor(byte[] anchor1, byte[] anchor2, CertificateForm certificateForm)
  {
    Assertions.assertNotNull(anchor1);
    Assertions.assertNotNull(anchor2);
    Assertions.assertNotNull(certificateForm);
    Assertions.assertArrayEquals(anchor1, anchor2);
    Assertions.assertArrayEquals(anchor2, getCertificateBytes(certificateForm.getCertificate()));
  }

  /**
   * convenience method to avoid handling exceptions in other methods for code readability
   */
  private byte[] getCertificateBytes(Certificate certificate)
  {
    Assertions.assertNotNull(certificate);
    try
    {
      return certificate.getEncoded();
    }
    catch (CertificateEncodingException e)
    {
      throw new IllegalStateException(e);
    }
  }

  /**
   * will check that the timer-configurations will have the correct values
   *
   * @param poseidasCoreConfiguration the direct read configuration
   * @param poseidasCoreConfigForm the read configuration by the form-element
   */
  private void checkTimerConfigurationForConfigDir1(PoseidasCoreConfiguration poseidasCoreConfiguration,
                                                    PoseidasCoreConfigForm poseidasCoreConfigForm)
  {
    TimerConfigurationType timerConfiguration1 = poseidasCoreConfiguration.getTimerConfiguration();
    TimerConfigurationType timerConfiguration2 = poseidasCoreConfigForm.getCoreConfig()
                                                                       .getTimerConfiguration();
    Assertions.assertNotNull(timerConfiguration1);
    Assertions.assertNotNull(timerConfiguration2);
    final int certRenewalLength = 2;
    Assertions.assertEquals(certRenewalLength, timerConfiguration2.getCertRenewal().getLength());
    Assertions.assertEquals(timerConfiguration1.getCertRenewal().getLength(),
                            timerConfiguration2.getCertRenewal().getLength());
    final int certRenewalUnit = 11;
    Assertions.assertEquals(certRenewalUnit, timerConfiguration2.getCertRenewal().getUnit());
    Assertions.assertEquals(timerConfiguration1.getCertRenewal().getUnit(),
                            timerConfiguration2.getCertRenewal().getUnit());
    final int blacklistRenewalLength = 2;
    Assertions.assertEquals(blacklistRenewalLength, timerConfiguration2.getBlacklistRenewal().getLength());
    Assertions.assertEquals(timerConfiguration1.getBlacklistRenewal().getLength(),
                            timerConfiguration2.getBlacklistRenewal().getLength());
    final int blacklistRenewalUnit = 11;
    Assertions.assertEquals(blacklistRenewalUnit, timerConfiguration2.getBlacklistRenewal().getUnit());
    Assertions.assertEquals(timerConfiguration1.getBlacklistRenewal().getUnit(),
                            timerConfiguration2.getBlacklistRenewal().getUnit());
    final int masterDefectlistRenewalLength = 2;
    Assertions.assertEquals(masterDefectlistRenewalLength,
                            timerConfiguration2.getMasterAndDefectListRenewal().getLength());
    Assertions.assertEquals(timerConfiguration1.getMasterAndDefectListRenewal().getLength(),
                            timerConfiguration2.getMasterAndDefectListRenewal().getLength());
    final int masterDefectlistRenewalUnit = 11;
    Assertions.assertEquals(masterDefectlistRenewalUnit,
                            timerConfiguration2.getMasterAndDefectListRenewal().getUnit());
    Assertions.assertEquals(timerConfiguration1.getMasterAndDefectListRenewal().getUnit(),
                            timerConfiguration2.getMasterAndDefectListRenewal().getUnit());
  }
}
