package de.governikus.eumw.poseidas.server.pki;

import java.security.KeyPairGenerator;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.SneakyThrows;


class RequestSignerCertificateServiceImplTest
{

  private static final String DEFAULT_PROVIDER = "providerA";

  private static final String DEFAULT_CVCREFID = "provider_a";

  private ConfigurationService configurationService;

  private TerminalPermissionAO facade;

  private RequestSignerCertificateService requestSignerCertificateService;

  @BeforeEach
  public void setUp()
  {
    configurationService = Mockito.mock(ConfigurationService.class);
    facade = Mockito.mock(TerminalPermissionAO.class);
    HSMServiceHolder hsmServiceHolder = Mockito.mock(HSMServiceHolder.class);
    requestSignerCertificateService = new RequestSignerCertificateServiceImpl(configurationService, facade,
                                                                              hsmServiceHolder);

  }

  @Test
  void testGenerateRSCSuccessPublic()
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(null);
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                36);
    Assertions.assertTrue(result);
  }


  @Test
  void testGenerateRSCSuccessPrivate()
  {
    var config = prepareConfiguration();
    config.getEidasConfiguration().setPublicServiceProviderName("other");
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(config));
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(null);
    Mockito.when(facade.getRequestSignerCertificateHolder(DEFAULT_CVCREFID)).thenReturn("rscChr");
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                "rscChr",
                                                                                                36);
    Assertions.assertTrue(result);
  }

  @Test
  void testGenerateRSCSuccessNonNullChrId() throws Exception
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(1);
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    kpg.initialize(256);
    Mockito.when(facade.getRequestSignerKey(DEFAULT_CVCREFID, true))
           .thenReturn(kpg.generateKeyPair().getPrivate().getEncoded());
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                36);
    Assertions.assertTrue(result);
  }

  @Test
  void testGenerateRSCPrivateNoRscChr()
  {
    var config = prepareConfiguration();
    config.getEidasConfiguration().setPublicServiceProviderName("other");
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(config));
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                36);
    Assertions.assertFalse(result);
  }

  @Test
  void testGenerateRSCWithLifespanToLong()
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                37);
    Assertions.assertFalse(result);
  }

  @SneakyThrows
  EidasMiddlewareConfig prepareConfiguration()
  {
    var configuration = ConfigurationTestHelper.createValidConfiguration();
    configuration.getEidasConfiguration().setCountryCode("DE");
    configuration.getEidasConfiguration().setPublicServiceProviderName(DEFAULT_PROVIDER);
    return configuration;
  }
}
