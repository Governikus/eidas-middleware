package de.governikus.eumw.poseidas.service;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class ConfigKeyDataServiceTest
{

  public static final String SIG_KEY = "sig-key";

  public static final String ANY_KEY = "anyKey";

  public static final String CLIENT_KEY = "client-key";

  public static final String META_CERT = "meta-cert";

  public static final String SERVER_CERT = "server-cert";

  public static final String MASTER_CERT = "master-cert";

  public static final String BLOCK_CERT = "block-cert";

  public static final String ANY_CERT = "cert";

  @Mock
  private ConfigurationService configurationService;

  @InjectMocks
  private ConfigKeyDataService configKeyDataService;

  //
  @Test
  void testIsKeyPairReferencedReturnsFalseWhenConfigurationMissing()
  {
    when(configurationService.getConfiguration()).thenReturn(Optional.empty());

    Assertions.assertFalse(configKeyDataService.isCertificateReferenced(ANY_CERT));
    Assertions.assertFalse(configKeyDataService.isKeyPairReferenced(ANY_KEY));
  }

  @Test
  void testIsKeyPairReferencedReturnsTrueForReferencedKeys()
  {
    EidasMiddlewareConfig config = mock(EidasMiddlewareConfig.class);

    EidasMiddlewareConfig.EidasConfiguration eidas = mock(EidasMiddlewareConfig.EidasConfiguration.class);
    EidasMiddlewareConfig.EidConfiguration eid = mock(EidasMiddlewareConfig.EidConfiguration.class);

    ServiceProviderType sp = mock(ServiceProviderType.class);

    when(config.getEidasConfiguration()).thenReturn(eidas);
    when(config.getEidConfiguration()).thenReturn(eid);

    when(eidas.getSignatureKeyPairName()).thenReturn(SIG_KEY);

    when(sp.getClientKeyPairName()).thenReturn(CLIENT_KEY);
    when(eid.getServiceProvider()).thenReturn(List.of(sp));

    when(configurationService.getConfiguration()).thenReturn(Optional.of(config));

    Assertions.assertTrue(configKeyDataService.isKeyPairReferenced(SIG_KEY));
    Assertions.assertTrue(configKeyDataService.isKeyPairReferenced(CLIENT_KEY));
    Assertions.assertFalse(configKeyDataService.isKeyPairReferenced(ANY_KEY));
  }

  @Test
  void testIsCertificateReferencedReturnsTrueForReferencedCertificates()
  {
    EidasMiddlewareConfig config = mock(EidasMiddlewareConfig.class);

    EidasMiddlewareConfig.EidasConfiguration eidas = mock(EidasMiddlewareConfig.EidasConfiguration.class);
    EidasMiddlewareConfig.EidConfiguration eid = mock(EidasMiddlewareConfig.EidConfiguration.class);

    DvcaConfigurationType dvca = mock(DvcaConfigurationType.class);

    when(config.getEidasConfiguration()).thenReturn(eidas);
    when(config.getEidConfiguration()).thenReturn(eid);

    when(eidas.getMetadataSignatureVerificationCertificateName()).thenReturn(META_CERT);

    when(eid.getDvcaConfiguration()).thenReturn(List.of(dvca));

    when(dvca.getServerSSLCertificateName()).thenReturn(SERVER_CERT);
    when(dvca.getMasterListTrustAnchorCertificateName()).thenReturn(MASTER_CERT);
    when(dvca.getBlackListTrustAnchorCertificateName()).thenReturn(BLOCK_CERT);

    when(configurationService.getConfiguration()).thenReturn(Optional.of(config));

    Assertions.assertTrue(configKeyDataService.isCertificateReferenced(META_CERT));
    Assertions.assertTrue(configKeyDataService.isCertificateReferenced(SERVER_CERT));
    Assertions.assertTrue(configKeyDataService.isCertificateReferenced(MASTER_CERT));
    Assertions.assertTrue(configKeyDataService.isCertificateReferenced(BLOCK_CERT));
    Assertions.assertFalse(configKeyDataService.isCertificateReferenced(ANY_CERT));
  }
}
