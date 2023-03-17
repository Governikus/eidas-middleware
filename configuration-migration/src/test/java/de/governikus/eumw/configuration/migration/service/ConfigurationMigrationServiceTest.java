package de.governikus.eumw.configuration.migration.service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerUnit;


class ConfigurationMigrationServiceTest
{

  private static final String TEST_RESOURCES_PATH = "src/test/resources";

  private static final String KEYS = "/keys";

  private static final String METADATA = "/metadata";

  private static final String POSEIDAS_XML = "/POSeIDAS.xml";

  private static final String EIDASMIDDLEWARE_PROPERTIES = "/eidasmiddleware.properties";

  private static final String GOV_DVCA_LOCALHOST = "localhost";

  private static final String GOV_DVCA_DVCA_R1_GOVERNIKUS_EID_DE = "dvca-r1.governikus-eid.de";

  private static final String BERCA_PS_1_1 = "berca-p1.d-trust.net";

  private static final String METADATA_SIGNATURE_VERIFICATION_CERTIFICATE = "metadataSignatureVerificationCertificate";

  private static final String MIDDLEWARE_SIGNING_KEY_PAIR = "middlewareSigningKeyPair";

  private static final String MIDDLEWARE_DECRYPTION_KEY_PAIR = "middlewareDecryptionKeyPair";

  private static final String BLACK_LIST_TRUST_ANCHOR = "BlackListTrustAnchor";

  private static final String MASTER_LIST_TRUST_ANCHOR = "MasterListTrustAnchor";

  private static final String SERVER_CERTIFICATE = "ServerCertificate";

  private static final String MIDDLEWARE = "middleware";

  private static final String WITHOUT_HSM = "/withoutHsm";

  private static final String WITH_HSM = "/withHsm";

  @TempDir
  File tempDir;


  @Test
  void testMigrateOldConfigWithOutHsm() throws Exception
  {
    File sourceKeys = new File(TEST_RESOURCES_PATH + KEYS);
    File destKeys = new File(tempDir.getAbsolutePath() + KEYS);
    FileUtils.copyDirectory(sourceKeys, destKeys);

    File sourceMetadata = new File(TEST_RESOURCES_PATH + METADATA);
    File destMetadata = new File(tempDir.getAbsolutePath() + METADATA);
    FileUtils.copyDirectory(sourceMetadata, destMetadata);

    File poseidasXml = new File(TEST_RESOURCES_PATH + WITHOUT_HSM + POSEIDAS_XML);
    File destPoseidas = new File(tempDir.getAbsolutePath() + POSEIDAS_XML);
    FileUtils.copyFile(poseidasXml, destPoseidas);

    File eidasProperties = new File(TEST_RESOURCES_PATH + WITHOUT_HSM + EIDASMIDDLEWARE_PROPERTIES);

    File destEidasProperties = new File(tempDir.getAbsolutePath() + EIDASMIDDLEWARE_PROPERTIES);
    FileUtils.copyFile(eidasProperties, destEidasProperties);
    setPathInConfig(destEidasProperties.toPath(), tempDir.toPath());

    ConfigurationMigrationService configurationMigrationService = new ConfigurationMigrationService();
    EidasMiddlewareConfig eidasMiddlewareConfig = configurationMigrationService.migrateOldConfig(tempDir.getAbsolutePath());
    Assertions.assertNotNull(eidasMiddlewareConfig);
    List<ServiceProviderType> serviceProviderList = eidasMiddlewareConfig.getEidConfiguration().getServiceProvider();
    Assertions.assertEquals(11, serviceProviderList.size());
    List<DvcaConfigurationType> dvcaConfigurationTypeList = eidasMiddlewareConfig.getEidConfiguration()
                                                                                 .getDvcaConfiguration();
    Assertions.assertEquals(3, dvcaConfigurationTypeList.size());
    List<CertificateType> certificates = eidasMiddlewareConfig.getKeyData().getCertificate();
    Assertions.assertEquals(10, certificates.size());
    List<KeyStoreType> keyStores = eidasMiddlewareConfig.getKeyData().getKeyStore();
    Assertions.assertEquals(13, keyStores.size());
    List<KeyPairType> keyPairs = eidasMiddlewareConfig.getKeyData().getKeyPair();
    Assertions.assertEquals(13, keyPairs.size());
    Assertions.assertEquals(1, eidasMiddlewareConfig.getEidasConfiguration().getConnectorMetadata().size());
    Assertions.assertEquals("https://localhost:8443", eidasMiddlewareConfig.getServerUrl());
    TimerConfigurationType timerConfiguration = eidasMiddlewareConfig.getEidConfiguration().getTimerConfiguration();

    Assertions.assertNotNull(timerConfiguration);
    Assertions.assertEquals(2, timerConfiguration.getCertRenewal().getLength());
    Assertions.assertEquals(TimerUnit.HOURS, timerConfiguration.getCertRenewal().getUnit());
    Assertions.assertEquals(20, timerConfiguration.getCertRenewal().getHoursRefreshCVCBeforeExpires());

    Assertions.assertEquals(2, timerConfiguration.getBlacklistRenewal().getLength());
    Assertions.assertEquals(TimerUnit.HOURS, timerConfiguration.getBlacklistRenewal().getUnit());

    Assertions.assertEquals(2, timerConfiguration.getMasterAndDefectListRenewal().getLength());
    Assertions.assertEquals(TimerUnit.HOURS, timerConfiguration.getMasterAndDefectListRenewal().getUnit());

    Assertions.assertEquals(12, timerConfiguration.getCrlRenewal().getLength());
    Assertions.assertEquals(TimerUnit.HOURS, timerConfiguration.getCrlRenewal().getUnit());

    assertServiceProvider(serviceProviderList, "DefaultProvider", "F", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "OtherDvca", "providerA", GOV_DVCA_DVCA_R1_GOVERNIKUS_EID_DE);
    assertServiceProvider(serviceProviderList, "TestbedA", "A", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedB", "B", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedC", "C", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedD", "D", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedECDSA", "ECDSA", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedEDSA", "EDSA", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedERSA", "ERSA", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedF", "F", GOV_DVCA_LOCALHOST);
    assertServiceProvider(serviceProviderList, "TestbedG", "G", BERCA_PS_1_1);

    assertDvca(dvcaConfigurationTypeList,
               GOV_DVCA_LOCALHOST,
               "https://localhost:8181/ca1/TA-Service",
               "https://localhost:8181/ca1/RI-Service",
               "https://localhost:8181/ca1/PA-Service",
               "https://localhost:8181/ca1/DVCA_CertDescriptionService");

    assertDvca(dvcaConfigurationTypeList,
               GOV_DVCA_DVCA_R1_GOVERNIKUS_EID_DE,
               "https://dvca-r1.governikus-eid.de:8444/gov_dvca/ta-service",
               "https://dvca-r1.governikus-eid.de:8444/gov_dvca/ri-service",
               "https://dvca-r1.governikus-eid.de:8444/gov_dvca/pa-service",
               "https://dvca-r1.governikus-eid.de:8444/gov_dvca/certDesc-service");
    assertDvca(dvcaConfigurationTypeList,
               BERCA_PS_1_1,
               "https://berca-p1.d-trust.net/ps/dvca-at/v1_1",
               "https://berca-p1.d-trust.net/ps/dvsd_v2/v1_1",
               "https://berca-p1.d-trust.net/ps/scs",
               "https://berca-p1.d-trust.net/ps/dvca-at-cert-desc");
    Assertions.assertEquals("A,ID,UB", eidasMiddlewareConfig.getEidConfiguration().getAllowedEidMeans());
    Assertions.assertEquals("providerA", eidasMiddlewareConfig.getEidasConfiguration().getPublicServiceProviderName());
    Assertions.assertEquals("DE", eidasMiddlewareConfig.getEidasConfiguration().getCountryCode());
    Assertions.assertTrue(eidasMiddlewareConfig.getEidasConfiguration().isDoSign());
    Assertions.assertEquals(30, eidasMiddlewareConfig.getEidasConfiguration().getMetadataValidity());
    Assertions.assertNotNull(eidasMiddlewareConfig.getEidasConfiguration().getContactPerson());
    Assertions.assertNotNull(eidasMiddlewareConfig.getEidasConfiguration().getOrganization());
    Assertions.assertEquals(MIDDLEWARE_DECRYPTION_KEY_PAIR,
                            eidasMiddlewareConfig.getEidasConfiguration().getDecryptionKeyPairName());
    Assertions.assertEquals(MIDDLEWARE_SIGNING_KEY_PAIR,
                            eidasMiddlewareConfig.getEidasConfiguration().getSignatureKeyPairName());
    Assertions.assertEquals(METADATA_SIGNATURE_VERIFICATION_CERTIFICATE,
                            eidasMiddlewareConfig.getEidasConfiguration()
                                                 .getMetadataSignatureVerificationCertificateName());
    assertCertificate(certificates, METADATA_SIGNATURE_VERIFICATION_CERTIFICATE);
    assertCertificate(certificates, GOV_DVCA_LOCALHOST + BLACK_LIST_TRUST_ANCHOR);
    assertCertificate(certificates, GOV_DVCA_LOCALHOST + MASTER_LIST_TRUST_ANCHOR);
    assertCertificate(certificates, GOV_DVCA_LOCALHOST + SERVER_CERTIFICATE);
    assertCertificate(certificates, GOV_DVCA_DVCA_R1_GOVERNIKUS_EID_DE + BLACK_LIST_TRUST_ANCHOR);
    assertCertificate(certificates, GOV_DVCA_DVCA_R1_GOVERNIKUS_EID_DE + MASTER_LIST_TRUST_ANCHOR);
    assertCertificate(certificates, GOV_DVCA_DVCA_R1_GOVERNIKUS_EID_DE + SERVER_CERTIFICATE);
    assertKeyPairAndKeyStore(keyPairs, keyStores, "DefaultProviderDvcaClientKeyPair", "DefaultProviderDvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "OtherDvcaDvcaClientKeyPair", "OtherDvcaDvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedADvcaClientKeyPair", "TestbedADvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedBDvcaClientKeyPair", "TestbedBDvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedCDvcaClientKeyPair", "TestbedCDvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedDDvcaClientKeyPair", "TestbedDDvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedECDSADvcaClientKeyPair", "TestbedECDSADvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedEDSADvcaClientKeyPair", "TestbedEDSADvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedERSADvcaClientKeyPair", "TestbedERSADvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedFDvcaClientKeyPair", "TestbedFDvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, "TestbedGDvcaClientKeyPair", "TestbedGDvcaKeyStore");
    assertKeyPairAndKeyStore(keyPairs, keyStores, MIDDLEWARE_DECRYPTION_KEY_PAIR, "middlewareDecryption", MIDDLEWARE);
    assertKeyPairAndKeyStore(keyPairs, keyStores, MIDDLEWARE_SIGNING_KEY_PAIR, "middlewareSigning", MIDDLEWARE);
  }


  @Test
  void testMigrateOldConfigWithHsm() throws Exception
  {
    File sourceKeys = new File(TEST_RESOURCES_PATH + KEYS);
    File destKeys = new File(tempDir.getAbsolutePath() + KEYS);
    FileUtils.copyDirectory(sourceKeys, destKeys);

    File sourceMetadata = new File(TEST_RESOURCES_PATH + METADATA);
    File destMetadata = new File(tempDir.getAbsolutePath() + METADATA);
    FileUtils.copyDirectory(sourceMetadata, destMetadata);

    File poseidasXml = new File(TEST_RESOURCES_PATH + WITH_HSM + POSEIDAS_XML);
    File destPoseidas = new File(tempDir.getAbsolutePath() + POSEIDAS_XML);
    FileUtils.copyFile(poseidasXml, destPoseidas);

    File eidasProperties = new File(TEST_RESOURCES_PATH + WITH_HSM + EIDASMIDDLEWARE_PROPERTIES);

    File destEidasProperties = new File(tempDir.getAbsolutePath() + EIDASMIDDLEWARE_PROPERTIES);
    FileUtils.copyFile(eidasProperties, destEidasProperties);
    setPathInConfig(destEidasProperties.toPath(), tempDir.toPath());

    ConfigurationMigrationService configurationMigrationService = new ConfigurationMigrationService();
    EidasMiddlewareConfig eidasMiddlewareConfig = configurationMigrationService.migrateOldConfig(tempDir.getAbsolutePath());
    Assertions.assertNotNull(eidasMiddlewareConfig);
    List<ServiceProviderType> serviceProviderList = eidasMiddlewareConfig.getEidConfiguration().getServiceProvider();
    Assertions.assertEquals(1, serviceProviderList.size());
    List<DvcaConfigurationType> dvcaConfigurationTypeList = eidasMiddlewareConfig.getEidConfiguration()
                                                                                 .getDvcaConfiguration();
    Assertions.assertEquals(1, dvcaConfigurationTypeList.size());
    List<CertificateType> certificates = eidasMiddlewareConfig.getKeyData().getCertificate();
    Assertions.assertEquals(4, certificates.size());
    List<KeyStoreType> keyStores = eidasMiddlewareConfig.getKeyData().getKeyStore();
    Assertions.assertEquals(1, keyStores.size());
    List<KeyPairType> keyPairs = eidasMiddlewareConfig.getKeyData().getKeyPair();
    Assertions.assertEquals(1, keyPairs.size());
    Assertions.assertNull(serviceProviderList.get(0).getClientKeyPairName());
    Assertions.assertNull(eidasMiddlewareConfig.getEidasConfiguration().getSignatureKeyPairName());
  }

  private void assertCertificate(List<CertificateType> certificateTypes, String certificateName)
  {
    List<CertificateType> certificate = certificateTypes.stream()
                                                        .filter(certificateType -> certificateType.getName()
                                                                                                  .equals(certificateName))
                                                        .collect(Collectors.toList());
    Assertions.assertEquals(1, certificate.size());
    Assertions.assertEquals(certificateName, certificate.get(0).getName());
  }

  private void assertServiceProvider(List<ServiceProviderType> serviceProviderList,
                                     String spName,
                                     String refId,
                                     String dvcaName)
  {
    List<ServiceProviderType> serviceProvider = serviceProviderList.stream()
                                                                   .filter(serviceProviderType -> serviceProviderType.getName()
                                                                                                                     .equals(spName))
                                                                   .collect(Collectors.toList());
    Assertions.assertEquals(1, serviceProvider.size());
    Assertions.assertEquals(spName, serviceProvider.get(0).getName());
    Assertions.assertEquals(refId, serviceProvider.get(0).getCVCRefID());
    Assertions.assertEquals(spName + "DvcaClientKeyPair", serviceProvider.get(0).getClientKeyPairName());
    Assertions.assertEquals(dvcaName, serviceProvider.get(0).getDvcaConfigurationName());
  }

  private void assertDvca(List<DvcaConfigurationType> dvcaConfigurationList,
                          String name,
                          String terminalAuthUrl,
                          String restrictedIdUrl,
                          String passiveAuthUrl,
                          String certDescUrl)
  {
    List<DvcaConfigurationType> dvca = dvcaConfigurationList.stream()
                                                            .filter(dvcaConfigurationType -> dvcaConfigurationType.getName()
                                                                                                                  .equals(name))
                                                            .collect(Collectors.toList());
    Assertions.assertEquals(1, dvca.size());
    Assertions.assertEquals(name, dvca.get(0).getName());
    Assertions.assertEquals(terminalAuthUrl, dvca.get(0).getTerminalAuthServiceUrl());
    Assertions.assertEquals(restrictedIdUrl, dvca.get(0).getRestrictedIdServiceUrl());
    Assertions.assertEquals(passiveAuthUrl, dvca.get(0).getPassiveAuthServiceUrl());
    Assertions.assertEquals(certDescUrl, dvca.get(0).getDvcaCertificateDescriptionServiceUrl());
    Assertions.assertEquals(name + BLACK_LIST_TRUST_ANCHOR, dvca.get(0).getBlackListTrustAnchorCertificateName());
    Assertions.assertEquals(name + MASTER_LIST_TRUST_ANCHOR, dvca.get(0).getMasterListTrustAnchorCertificateName());
    Assertions.assertEquals(name + SERVER_CERTIFICATE, dvca.get(0).getServerSSLCertificateName());
  }

  private void assertKeyPairAndKeyStore(List<KeyPairType> keyPairs,
                                        List<KeyStoreType> keyStores,
                                        String keyPairName,
                                        String keyStoreName,
                                        String... optionalAlias)
  {
    List<KeyPairType> keyPair = keyPairs.stream()
                                        .filter(keyPairType -> keyPairType.getName().equals(keyPairName))
                                        .collect(Collectors.toList());
    Assertions.assertEquals(1, keyPair.size());
    Assertions.assertEquals(keyPairName, keyPair.get(0).getName());
    String alias = optionalAlias.length == 0 ? keyPairName : optionalAlias[0];
    Assertions.assertEquals(alias, keyPair.get(0).getAlias());
    Assertions.assertEquals(keyStoreName, keyPair.get(0).getKeyStoreName());
    Assertions.assertEquals(1,
                            keyStores.stream()
                                     .filter(keyStoreType -> keyStoreType.getName().equals(keyStoreName))
                                     .count());
  }


  /**
   * Read the config file, replace the placeholder $CONFIGPATH with the real path to this config directory and save the
   * config file
   *
   * @param pathToConfigFile The path to the file that should be adjusted
   * @param pathToConfigDir The path to the config directory
   */
  private void setPathInConfig(Path pathToConfigFile, Path pathToConfigDir) throws IOException
  {
    String content = Files.readString(pathToConfigFile);
    String escapedPath = pathToConfigDir.toString().replace("\\", "/");
    content = content.replace("$CONFIGPATH", escapedPath);
    Files.write(pathToConfigFile, content.getBytes(StandardCharsets.UTF_8));
  }
}
