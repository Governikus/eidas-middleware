package de.governikus.eumw.poseidas.server.pki;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.service.ConfigHolderInterface;


class RequestSignerCertificateServiceImplTest
{

  private static final String DEFAULT_PROVIDER = "providerA";

  private static final String DEFAULT_CVCREFID = "provider_a";

  private ConfigHolderInterface configHolder;

  private TerminalPermissionAO facade;

  private HSMServiceHolder hsmServiceHolder;

  private RequestSignerCertificateService requestSignerCertificateService;

  @BeforeEach
  public void setUp()
  {
    configHolder = Mockito.mock(ConfigHolderInterface.class);
    facade = Mockito.mock(TerminalPermissionAO.class);
    hsmServiceHolder = Mockito.mock(HSMServiceHolder.class);
    requestSignerCertificateService = new RequestSignerCertificateServiceImpl(configHolder, facade,
                                                                              hsmServiceHolder);
    Security.addProvider(new BouncyCastleProvider());
    Path resourceDirectory = Paths.get("src", "test", "resources");
    System.setProperty("spring.config.additional-location", resourceDirectory.toFile().getAbsolutePath());
  }

  @AfterAll
  public static void afterAll()
  {
    System.clearProperty("spring.config.additional-location");
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    PoseidasConfigurator.reset();
  }

  @Test
  void testGenerateRSCFailure()
  {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Mockito.when(configHolder.getCountryCode()).thenReturn("DE");
    Mockito.when(configHolder.getEntityIDInt()).thenReturn(DEFAULT_PROVIDER);
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(null);
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                36);
    Assertions.assertFalse(result);
  }

  @Test
  void testGenerateRSCSuccessPublic()
  {
    Mockito.when(configHolder.getCountryCode()).thenReturn("DE");
    Mockito.when(configHolder.getEntityIDInt()).thenReturn("other");
    Mockito.when(configHolder.getEntityIDInt()).thenReturn(DEFAULT_PROVIDER);
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(null);
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                36);

    Assertions.assertTrue(result);
  }


  @Test
  void testGenerateRSCSuccessPrivate()
  {
    Mockito.when(configHolder.getCountryCode()).thenReturn("DE");
    Mockito.when(configHolder.getEntityIDInt()).thenReturn("other");
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(null);
    Mockito.when(facade.getRequestSignerCertificateHolder(DEFAULT_CVCREFID)).thenReturn("rscChr");
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                Mockito.anyString(),
                                                                                                36);
    Assertions.assertTrue(result);
  }

  @Test
  void testGenerateRSCSuccessNonNullChrId() throws Exception
  {
    Mockito.when(configHolder.getCountryCode()).thenReturn("DE");
    Mockito.when(configHolder.getEntityIDInt()).thenReturn(DEFAULT_PROVIDER);
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(1);
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
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
    Mockito.when(configHolder.getCountryCode()).thenReturn("DE");
    Mockito.when(configHolder.getEntityIDInt()).thenReturn("other");
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                36);
    Assertions.assertFalse(result);
  }

  @Test
  void testGenerateRSCWithLifespanToLong()
  {
    Mockito.when(configHolder.getCountryCode()).thenReturn("DE");
    Mockito.when(configHolder.getEntityIDInt()).thenReturn(DEFAULT_PROVIDER);
    boolean result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                null,
                                                                                                37);
    Assertions.assertFalse(result);
  }
}
