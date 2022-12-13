/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.utils.xml.XmlException;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@DataJpaTest
class ConfigurationServiceTest
{

  private static final String PASSWORD = "123456";

  private static final String PKCS_12_KEYSTORE = "pkcs12-keystore";

  private static final String JKS_KEYSTORE = "jks-keystore";

  // Service to be tested
  private ConfigurationService configurationService;

  // To reset the database
  @Autowired
  private ConfigurationRepository configurationRepository;

  @BeforeEach
  void setUp()
  {
    configurationService = new ConfigurationService(configurationRepository);
  }

  @AfterEach
  void cleanUp()
  {
    configurationRepository.deleteAll();
  }

  @Test
  void testLoadEmpty()
  {
    Assertions.assertTrue(configurationService.getConfiguration().isEmpty());
  }

  @Test
  void testSaveAndLoad() throws Exception
  {
    // Prepare configuration
    EidasMiddlewareConfig config = ConfigurationTestHelper.createValidConfiguration();

    // Save the configuration
    var returnedConfig = configurationService.saveConfiguration(config, true);
    Assertions.assertEquals(config, returnedConfig);

    // Load the configuration
    Assertions.assertEquals(config, configurationService.getConfiguration().get());

    // Save the configuration as an XML string
    var configString = XmlHelper.marshalObject(config);
    var returnedConfigString = configurationService.saveConfiguration(configString, true);
    Assertions.assertEquals(configString, returnedConfigString);

    // Load the configuration
    Assertions.assertEquals(config, configurationService.getConfiguration().get());
  }

  @Test
  void testGetKeyPairs() throws Exception
  {
    // Save a configuration with two key stores and their respective key pairs
    var configuration = ConfigurationTestHelper.createValidConfiguration();
    configuration.getKeyData()
                 .getKeyStore()
                 .add(new KeyStoreType(PKCS_12_KEYSTORE,
                                       ConfigurationServiceTest.class.getResourceAsStream("/configuration/keystore.p12")
                                                                     .readAllBytes(),
                                       KeyStoreTypeType.PKCS_12, PASSWORD));
    configuration.getKeyData()
                 .getKeyPair()
                 .add(new KeyPairType("pkcs12-keypair", PKCS_12_KEYSTORE, PASSWORD, PKCS_12_KEYSTORE));

    configuration.getKeyData()
                 .getKeyStore()
                 .add(new KeyStoreType(JKS_KEYSTORE,
                                       ConfigurationServiceTest.class.getResourceAsStream("/configuration/keystore.jks")
                                                                     .readAllBytes(),
                                       KeyStoreTypeType.JKS, PASSWORD));
    configuration.getKeyData().getKeyPair().add(new KeyPairType("jks-keypair", JKS_KEYSTORE, PASSWORD, JKS_KEYSTORE));

    configurationService.saveConfiguration(configuration, true);

    // Get the PKCS12 key store
    var keyPair = configurationService.getKeyPair("pkcs12-keypair");
    Assertions.assertNotNull(keyPair.getKey());
    Assertions.assertNotNull(keyPair.getCertificate());

    // Get the JKS key store
    keyPair = configurationService.getKeyPair("jks-keypair");
    Assertions.assertNotNull(keyPair.getKey());
    Assertions.assertNotNull(keyPair.getCertificate());
  }

  @Test
  void testGetKeyPairInvalidAlias() throws Exception
  {
    // save the configuration without keyData
    var configuration = configurationService.saveConfiguration(ConfigurationTestHelper.createValidConfiguration(),
                                                               true);

    // Save a configuration with an invalid alias
    configuration.getKeyData()
                 .getKeyStore()
                 .add(new KeyStoreType(PKCS_12_KEYSTORE,
                                       ConfigurationServiceTest.class.getResourceAsStream("/configuration/keystore.p12")
                                                                     .readAllBytes(),
                                       KeyStoreTypeType.PKCS_12, PASSWORD));
    configuration.getKeyData()
                 .getKeyPair()
                 .add(new KeyPairType("pkcs12-keypair", "invalid-alias", PASSWORD, PKCS_12_KEYSTORE));
    configurationService.saveConfiguration(configuration, true);

    // Try to get the key pair with the invalid alias
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getKeyPair("pkcs12-keypair"));
  }

  @Test
  void testGetKeyPairInvalidPassword() throws Exception
  {
    // save the configuration without keyData
    var configuration = configurationService.saveConfiguration(ConfigurationTestHelper.createValidConfiguration(),
                                                               true);

    // Save a configuration with an invalid key store password
    configuration.getKeyData()
                 .getKeyStore()
                 .add(new KeyStoreType(JKS_KEYSTORE,
                                       ConfigurationServiceTest.class.getResourceAsStream("/configuration/keystore.jks")
                                                                     .readAllBytes(),
                                       KeyStoreTypeType.JKS, "invalid"));
    configuration.getKeyData().getKeyPair().add(new KeyPairType("jks-keypair", JKS_KEYSTORE, PASSWORD, JKS_KEYSTORE));
    configurationService.saveConfiguration(configuration, true);

    // Try to get the key pair with the key store password
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getKeyPair("pkcs12-keypair"));

    // Save a configuration with an invalid key password
    configuration.getKeyData()
                 .getKeyStore()
                 .add(new KeyStoreType(JKS_KEYSTORE,
                                       ConfigurationServiceTest.class.getResourceAsStream("/configuration/keystore.jks")
                                                                     .readAllBytes(),
                                       KeyStoreTypeType.JKS, PASSWORD));
    configuration.getKeyData().getKeyPair().add(new KeyPairType("jks-keypair", JKS_KEYSTORE, "invalid", JKS_KEYSTORE));
    configurationService.saveConfiguration(configuration, true);

    // Try to get the key pair with the key password
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getKeyPair("jks-keypair"));
  }



  @Test
  void testGetKeyPairWithMissingConfiguration() throws Exception
  {
    // get a key pair without any configuration
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getKeyPair("keyStoreName"));

    // save the configuration without keyData
    configurationService.saveConfiguration(ConfigurationTestHelper.createValidConfiguration(), true);

    // get a key pair without any keyData present
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getKeyPair("keyStoreName"));
  }

  @Test
  void testGetCertificate() throws Exception
  {
    // save the configuration without keyData
    var configuration = configurationService.saveConfiguration(ConfigurationTestHelper.createValidConfiguration(),
                                                               true);

    // get a certificate with any certificates present
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getCertificate("certificateName"));

    // add a certificate to the configuration
    configuration.getKeyData()
                 .getCertificate()
                 .add(new CertificateType("certificateName",
                                          ConfigurationServiceTest.class.getResourceAsStream("/configuration/jks-keystore.cer")
                                                                        .readAllBytes(),
                                          null, null));
    configurationService.saveConfiguration(configuration, true);

    // Get an unknown certificate
    Assertions.assertThrows(ConfigurationException.class,
                            () -> configurationService.getCertificate("unknown-certificate"));

    // Get the certificate
    Assertions.assertEquals("CN=jks-keystore",
                            configurationService.getCertificate("certificateName").getSubjectDN().getName());

  }

  @Test
  void testGetServerURLWithEidasContextPath() throws Exception
  {
    // Test valid server URL
    var configuration = ConfigurationTestHelper.createValidConfiguration();
    configurationService.saveConfiguration(configuration, true);
    Assertions.assertEquals("http://serverURL/eidas-middleware",
                            configurationService.getServerURLWithEidasContextPath());

    configuration.setServerUrl("https://serverURL:8443");
    configurationService.saveConfiguration(configuration, true);
    Assertions.assertEquals("https://serverURL:8443/eidas-middleware",
                            configurationService.getServerURLWithEidasContextPath());

    // Test invalid or empty URL
    configuration.setServerUrl("invalid");
    configurationService.saveConfiguration(configuration, true);
    Assertions.assertThrows(ConfigurationException.class,
                            () -> configurationService.getServerURLWithEidasContextPath());

    configuration.setServerUrl("");
    configurationService.saveConfiguration(configuration, true);
    Assertions.assertThrows(ConfigurationException.class,
                            () -> configurationService.getServerURLWithEidasContextPath());
  }

  @Test
  void testConfigurationValidity() throws Exception
  {
    EidasMiddlewareConfig invalidConfig = ConfigurationTestHelper.createInvalidConfiguration();
    EidasMiddlewareConfig validConfig = ConfigurationTestHelper.createValidConfiguration();
    Assertions.assertDoesNotThrow(() -> configurationService.saveConfiguration(validConfig, true));
    // Checking invalid configuration for validity
    Assertions.assertThrows(XmlException.class, () -> configurationService.saveConfiguration(invalidConfig, true));
    Assertions.assertDoesNotThrow(() -> configurationService.saveConfiguration(validConfig, false));
    Assertions.assertDoesNotThrow(() -> configurationService.saveConfiguration(invalidConfig, false));
  }

  @Test
  void testGetProviderWithErrors() throws Exception
  {
    // Missing configuration
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getProviderByEntityID(""));

    // Configuration without the name for the signature validation certificate
    EidasMiddlewareConfig validConfig = ConfigurationTestHelper.createValidConfiguration();
    configurationService.saveConfiguration(validConfig, false);
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getProviderByEntityID(""));

    // Configuration without the certificate
    validConfig.getEidasConfiguration().setMetadataSignatureVerificationCertificateName("nonexisting");
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getProviderByEntityID(""));
  }

  @Test
  void testGetProvider() throws Exception
  {
    // Prepare configuration with certificate and two metadata entries, one with a valid signature and the other one is
    // invalid
    EidasMiddlewareConfig validConfig = ConfigurationTestHelper.createValidConfiguration();
    validConfig.getKeyData()
               .getCertificate()
               .add(new CertificateType("sigCert",
                                        ConfigurationServiceTest.class.getResourceAsStream("/configuration/sigCert.crt")
                                                                      .readAllBytes(),
                                        null, null));
    validConfig.getEidasConfiguration().setMetadataSignatureVerificationCertificateName("sigCert");
    validConfig.getEidasConfiguration()
               .getConnectorMetadata()
               .add(new ConnectorMetadataType(ConfigurationServiceTest.class.getResourceAsStream("/configuration/demo_epa.xml")
                                                                            .readAllBytes(),
                                              "https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa"));
    validConfig.getEidasConfiguration()
               .getConnectorMetadata()
               .add(new ConnectorMetadataType(ConfigurationServiceTest.class.getResourceAsStream("/configuration/demo_epa_20.xml")
                                                                            .readAllBytes(),
                                              "https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_20"));
    validConfig.getEidasConfiguration()
               .getConnectorMetadata()
               .add(new ConnectorMetadataType(ConfigurationServiceTest.class.getResourceAsStream("/configuration/demo_epa_invalid.xml")
                                                                            .readAllBytes(),
                                              "https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_invalid"));
    configurationService.saveConfiguration(validConfig, false);

    // Get Provider
    Assertions.assertNotNull(configurationService.getProviderByEntityID("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa"));
    Assertions.assertNotNull(configurationService.getProviderByEntityID("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_20"));
    Assertions.assertThrows(ConfigurationException.class,
                            () -> configurationService.getProviderByEntityID("https://demo.mein-servicekonto.de/EidasNode/ConnectorMetadata?SP=demo_epa_invalid"));
  }

  @Test
  void testDownloadConfigWithoutKeys() throws Exception
  {
    EidasMiddlewareConfig config = ConfigurationTestHelper.createValidConfiguration();
    KeyStoreType keyStoreType = new KeyStoreType();
    keyStoreType.setKeyStore("blub".getBytes(StandardCharsets.UTF_8));
    keyStoreType.setType(KeyStoreTypeType.JKS);
    keyStoreType.setName("blub");
    keyStoreType.setPassword("123456");
    config.getKeyData().getKeyStore().add(keyStoreType);
    KeyPairType keyPairType = new KeyPairType();
    keyPairType.setKeyStoreName("blub");
    keyPairType.setAlias("blub");
    keyPairType.setName("blub");
    keyPairType.setPassword("123456");
    config.getKeyData().getKeyPair().add(keyPairType);
    configurationService.saveConfiguration(config, true);
    Optional<EidasMiddlewareConfig> returnedConfig = configurationService.downloadConfigWithoutKeys();
    returnedConfig.get().getKeyData().getKeyPair().forEach(kp -> Assertions.assertNull(kp.getPassword()));
    returnedConfig.get().getKeyData().getKeyStore().forEach(ks -> {
      Assertions.assertNull(ks.getKeyStore());
      Assertions.assertNull(ks.getPassword());
    });
  }

  @Test
  void testDownloadNonExistingConfigWithoutKeys()
  {
    Optional<EidasMiddlewareConfig> returnedConfig = configurationService.downloadConfigWithoutKeys();
    Assertions.assertTrue(returnedConfig.isEmpty());
  }

  @Test
  void testGetDvcaConfiguration() throws Exception
  {
    var configuration = configurationService.saveConfiguration(ConfigurationTestHelper.createValidConfiguration(),
                                                               true);
    var sp = new ServiceProviderType();
    sp.setName("UnknownSP");
    Assertions.assertThrows(ConfigurationException.class, () -> configurationService.getDvcaConfiguration(sp));
    DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(configuration.getEidConfiguration()
                                                                                                     .getServiceProvider()
                                                                                                     .get(0));
    Assertions.assertNotNull(dvcaConfiguration);
    Assertions.assertEquals(configuration.getEidConfiguration().getDvcaConfiguration().get(0), dvcaConfiguration);
  }
}
