package de.governikus.eumw.poseidas.server.idprovider.config;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * This helper class provides configurations for testing
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ConfigurationTestHelper
{

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
    dvcaConfiguration.setDvcaCertificateDescriptionServiceUrl("cdurl");
    dvcaConfiguration.setMasterListTrustAnchorCertificateName("masterListTrustAnchor");
    eidConfiguration.getDvcaConfiguration().add(dvcaConfiguration);
    eidConfiguration.getServiceProvider()
                    .add(new ServiceProviderType("sp-name", true, "cvcRefId", "dvcaConfName", "clientKeyName"));
    TimerConfigurationType timerConfigurationType = new TimerConfigurationType();
    timerConfigurationType.setCertRenewal(new TimerTypeCertRenewal(1, TimerUnit.MINUTES, 1));
    timerConfigurationType.setBlacklistRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setMasterAndDefectListRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setCrlRenewal(new TimerType(1, TimerUnit.MINUTES));
    eidConfiguration.setTimerConfiguration(timerConfigurationType);
    config.setEidConfiguration(eidConfiguration);
    var keyData = new EidasMiddlewareConfig.KeyData();
    CertificateFactory cf = CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    X509Certificate masterListTrustAnchor = (X509Certificate)cf.generateCertificate(ConfigurationTestHelper.class.getResourceAsStream("/TEST_csca_germany.cer"));
    var certificateType = new CertificateType("masterListTrustAnchor", masterListTrustAnchor.getEncoded(), null, null);
    keyData.getCertificate().add(certificateType);
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
}
