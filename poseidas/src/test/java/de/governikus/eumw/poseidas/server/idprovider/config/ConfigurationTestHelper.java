package de.governikus.eumw.poseidas.server.idprovider.config;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.EntanglementTimerType;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * This helper class provides configurations for testing
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ConfigurationTestHelper
{

  public static final String CVC_REF_ID = "cvcRefId";

  public static final String SP_NAME = "sp-name";

  /**
   * This method generates a configuration for testing
   *
   * @return A configuration for testing
   */
  public static EidasMiddlewareConfig createValidConfiguration() throws Exception
  {
    EidasMiddlewareConfig config = new EidasMiddlewareConfig();
    config.setServerUrl("http://serverURL");
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.getConnectorMetadata()
                      .add(new ConnectorMetadataType("metadata".getBytes(StandardCharsets.UTF_8), null));
    eidasConfiguration.setDoSign(true);
    eidasConfiguration.setCountryCode("DE");
    config.setEidasConfiguration(eidasConfiguration);
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    DvcaConfigurationType dvcaConfiguration = new DvcaConfigurationType();
    dvcaConfiguration.setName("dvcaConfName");
    dvcaConfiguration.setTerminalAuthServiceUrl("taurl");
    dvcaConfiguration.setRestrictedIdServiceUrl("riurl");
    dvcaConfiguration.setPassiveAuthServiceUrl("paurl");
    dvcaConfiguration.setMasterListTrustAnchorCertificateName("masterListTrustAnchor");
    dvcaConfiguration.setBlackListTrustAnchorCertificateName("blockListTrustAnchor");
    eidConfiguration.getDvcaConfiguration().add(dvcaConfiguration);
    eidConfiguration.getServiceProvider()
                    .add(new ServiceProviderType(SP_NAME, true, CVC_REF_ID, "dvcaConfName", "clientKeyName", null));
    TimerConfigurationType timerConfigurationType = new TimerConfigurationType();
    timerConfigurationType.setCertRenewal(new TimerTypeCertRenewal(1, TimerUnit.MINUTES, 1));
    timerConfigurationType.setBlacklistRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setMasterAndDefectListRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setCrlRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setTlsEntangleRenewal(new EntanglementTimerType(1, TimerUnit.HOURS, true));
    eidConfiguration.setTimerConfiguration(timerConfigurationType);
    config.setEidConfiguration(eidConfiguration);
    var keyData = new EidasMiddlewareConfig.KeyData();
    CertificateFactory cf = CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    X509Certificate masterListTrustAnchor = (X509Certificate)cf.generateCertificate(ConfigurationTestHelper.class.getResourceAsStream("/TEST_csca_germany.cer"));
    var masterListTrustAnchorCertificate = new CertificateType("masterListTrustAnchor",
                                                               masterListTrustAnchor.getEncoded(), null, null);
    keyData.getCertificate().add(masterListTrustAnchorCertificate);
    X509Certificate blockListTrustAnchor = (X509Certificate)cf.generateCertificate(ConfigurationTestHelper.class.getResourceAsStream("/blockList/bl-trust-anchor.cer"));
    var blockListTrustAnchorCertificate = new CertificateType("blockListTrustAnchor", blockListTrustAnchor.getEncoded(),
                                                              null, null);
    keyData.getCertificate().add(blockListTrustAnchorCertificate);
    config.setKeyData(keyData);
    return config;
  }

  public static EidasMiddlewareConfig createInvalidConfiguration()
  {
    EidasMiddlewareConfig config = new EidasMiddlewareConfig();
    config.setServerUrl("http://serverURL");
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.getConnectorMetadata()
                      .add(new ConnectorMetadataType("metadata".getBytes(StandardCharsets.UTF_8), null));
    eidasConfiguration.setDoSign(true);
    eidasConfiguration.setCountryCode("DE");
    config.setEidasConfiguration(eidasConfiguration);
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    DvcaConfigurationType dvcaConfiguration = new DvcaConfigurationType();
    dvcaConfiguration.setName("name");
    eidConfiguration.getDvcaConfiguration().add(dvcaConfiguration);
    TimerConfigurationType timerConfigurationType = new TimerConfigurationType();
    timerConfigurationType.setCertRenewal(new TimerTypeCertRenewal(1, TimerUnit.MINUTES, 1));
    timerConfigurationType.setBlacklistRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setMasterAndDefectListRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setCrlRenewal(new TimerType(1, TimerUnit.MINUTES));
    eidConfiguration.setTimerConfiguration(timerConfigurationType);
    config.setEidConfiguration(eidConfiguration);
    var keyData = new EidasMiddlewareConfig.KeyData();
    config.setKeyData(keyData);
    return config;
  }

  public static EidasMiddlewareConfig createConfigurationWithClientKeyPair() throws Exception
  {
    EidasMiddlewareConfig configuration = ConfigurationTestHelper.createValidConfiguration();

    KeyStoreType keyStoreType = new KeyStoreType("client-keystore",
                                                 ConfigurationTestHelper.class.getResourceAsStream("/configuration/keystore.p12")
                                                                              .readAllBytes(),
                                                 KeyStoreTypeType.PKCS_12, "123456");
    configuration.getKeyData().getKeyStore().add(keyStoreType);
    KeyPairType keyPairType = new KeyPairType("client-keypair", "pkcs12-keystore", "123456", "client-keystore");
    configuration.getKeyData().getKeyPair().add(keyPairType);
    ServiceProviderType serviceProviderType = configuration.getEidConfiguration()
                                                           .getServiceProvider()
                                                           .stream()
                                                           .filter(sp -> ConfigurationTestHelper.SP_NAME.equals(sp.getName()))
                                                           .findFirst()
                                                           .orElseThrow();
    serviceProviderType.setClientKeyPairName("client-keypair");
    DvcaConfigurationType dvcaConfigurationType = configuration.getEidConfiguration().getDvcaConfiguration().get(0);
    dvcaConfigurationType.setRestrictedIdServiceUrl("https://some-url.de");

    return configuration;
  }

  public static KeyPair getKeyPair(String keyPairName, EidasMiddlewareConfig configuration)
  {
    var keyPairType = configuration.getKeyData()
                                   .getKeyPair()
                                   .stream()
                                   .filter(k -> k.getName().equals(keyPairName))
                                   .findFirst()
                                   .orElseThrow(() -> new ConfigurationException("No key pair available with name "
                                                                                 + keyPairName));

    return configuration.getKeyData()
                        .getKeyStore()
                        .stream()
                        .filter(k -> k.getName().equals(keyPairType.getKeyStoreName()))
                        .findFirst()
                        .map(keyStoreType -> new KeyPair(KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                                                                        KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                                                                           .value()),
                                                                                        keyStoreType.getPassword()),
                                                         keyPairType.getAlias(), keyPairType.getPassword()))
                        .orElseThrow();
  }
}
