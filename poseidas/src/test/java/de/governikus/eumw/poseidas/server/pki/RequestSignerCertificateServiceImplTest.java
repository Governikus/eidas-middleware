package de.governikus.eumw.poseidas.server.pki;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthServiceBean;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate.Status;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.KeyStoreSupporter.KeyStoreType;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.SneakyThrows;


class RequestSignerCertificateServiceImplTest
{

  private static final String DEFAULT_PROVIDER = "providerA";

  private static final String DEFAULT_CVCREFID = "provider_a";

  private ConfigurationService configurationService;

  private TerminalPermissionAO facade;

  private TermAuthServiceBean termAuthServiceBean;

  private RequestSignerCertificateServiceImpl requestSignerCertificateService;

  @BeforeEach
  public void setUp()
  {
    configurationService = Mockito.mock(ConfigurationService.class);
    facade = Mockito.mock(TerminalPermissionAO.class);
    termAuthServiceBean = Mockito.mock(TermAuthServiceBean.class);
    HSMServiceHolder hsmServiceHolder = Mockito.mock(HSMServiceHolder.class);
    TimerHistoryService timerHistoryService = Mockito.mock(TimerHistoryService.class);
    requestSignerCertificateService = new RequestSignerCertificateServiceImpl(configurationService, facade,
                                                                              hsmServiceHolder, termAuthServiceBean,
                                                                              timerHistoryService);
  }

  @Test
  void testGenerateRSCSuccessPublic()
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(null);
    Optional<String> result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                         null,
                                                                                                         36);
    Assertions.assertTrue(result.isEmpty());
  }


  @Test
  void testGenerateRSCSuccessPrivate()
  {
    var config = prepareConfiguration();
    config.getEidasConfiguration().setPublicServiceProviderName("other");
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(config));
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(null);
    Mockito.when(facade.getRequestSignerCertificateHolder(DEFAULT_CVCREFID)).thenReturn("rscChr");
    Optional<String> result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                         "rscChr",
                                                                                                         36);
    Assertions.assertTrue(result.isEmpty());
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
    Optional<String> result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                         null,
                                                                                                         36);
    Assertions.assertTrue(result.isEmpty());
  }

  @Test
  void testGenerateRSCPrivateNoRscChr()
  {
    var config = prepareConfiguration();
    config.getEidasConfiguration().setPublicServiceProviderName("other");
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(config));
    Optional<String> result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                         null,
                                                                                                         36);
    Assertions.assertTrue(result.isPresent());
  }

  @Test
  void testGenerateRSCWithLifespanToLong()
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Optional<String> result = requestSignerCertificateService.generateNewPendingRequestSignerCertificate(DEFAULT_PROVIDER,
                                                                                                         null,
                                                                                                         37);
    Assertions.assertTrue(result.isPresent());
  }

  @Test
  void testBuildCmsContainerWithPending() throws Exception
  {
    EidasMiddlewareConfig config = prepareConfiguration();
    ServiceProviderType sp = new ServiceProviderType();
    sp.setName(DEFAULT_PROVIDER);
    sp.setCVCRefID(DEFAULT_CVCREFID);
    config.getEidConfiguration().getServiceProvider().add(sp);
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(config));

    // no pending RSC, no CMS
    Assertions.assertTrue(requestSignerCertificateService.buildCmsContainerWithPending(DEFAULT_PROVIDER).isEmpty());

    KeyStore ks = KeyStoreSupporter.readKeyStore(RequestSignerCertificateServiceImplTest.class.getResource("/configuration/ec.jks")
                                                                                              .openStream(),
                                                 KeyStoreType.JKS,
                                                 "123456");
    X509Certificate cert = (X509Certificate)ks.getCertificate("ec");
    byte[] key = ks.getKey("ec", "123456".toCharArray()).getEncoded();
    Mockito.when(facade.getRequestSignerCertificate(DEFAULT_CVCREFID, false)).thenReturn(cert);
    Mockito.when(facade.getRequestSignerKey(DEFAULT_CVCREFID, false)).thenReturn(key);

    // no current RSC, no CMS
    Assertions.assertTrue(requestSignerCertificateService.buildCmsContainerWithPending(DEFAULT_PROVIDER).isEmpty());

    Mockito.when(facade.getRequestSignerCertificate(DEFAULT_CVCREFID, true)).thenReturn(cert);
    Mockito.when(facade.getRequestSignerKey(DEFAULT_CVCREFID, true)).thenReturn(key);

    // with current and pending RSC we expect a CMS
    Optional<byte[]> cms = requestSignerCertificateService.buildCmsContainerWithPending(DEFAULT_PROVIDER);
    Assertions.assertTrue(cms.isPresent());
    new CMSSignedData(cms.get());
  }

  @Test
  void testRenewRsc() throws Exception
  {
    // Load Key Store to simulate current RSC and pending RSC
    KeyStore ks = KeyStoreSupporter.readKeyStore(RequestSignerCertificateServiceImplTest.class.getResource("/configuration/ec.jks")
                                                                                              .openStream(),
                                                 KeyStoreType.JKS,
                                                 "123456");
    X509Certificate cert = (X509Certificate)ks.getCertificate("ec");
    byte[] key = ks.getKey("ec", "123456".toCharArray()).getEncoded();
    // Prepare Configuration
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    // Mock calls for current RSC
    Mockito.when(facade.getRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, true)).thenReturn(cert);
    Mockito.when(facade.getRequestSignerKey(ConfigurationTestHelper.CVC_REF_ID, true)).thenReturn(key);
    // Mock calls for pending RSC. Attention the getPendingRSC is called twice. Once when a new RSC is generated and
    // once when the CMS container is build. For the first call <null> is returned for the second call the prepared RSC
    Mockito.when(facade.getRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, false))
           .thenReturn(null)
           .thenReturn(cert);
    Mockito.when(facade.getRequestSignerCertificateHolder(ConfigurationTestHelper.CVC_REF_ID)).thenReturn("rscChr");
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(1);
    // Mock calls for pending RSC status. Attention the getPendingRscStatus is called twice. Once as a check whether a
    // pending RSC still exists, once as a check whether to send it. For the first call <null> is returned, for the
    // second call READY_TO_SEND
    Mockito.when(facade.getPendingRscStatus(ConfigurationTestHelper.CVC_REF_ID))
           .thenReturn(null)
           .thenReturn(Status.READY_TO_SEND);
    TermAuthService termAuthService = Mockito.mock(TermAuthService.class);
    Mockito.when(termAuthServiceBean.getTermAuthService(ConfigurationTestHelper.SP_NAME)).thenReturn(termAuthService);
    Optional<String> result = requestSignerCertificateService.renewRSC(ConfigurationTestHelper.SP_NAME);
    Assertions.assertTrue(result.isEmpty());
    Mockito.verify(facade).makePendingRscToCurrentRsc(ConfigurationTestHelper.CVC_REF_ID, true);
  }

  @Test
  void testRenewRscFailed() throws Exception
  {
    // With a wrong SP-Name no RSC can be generated
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Optional<String> result = requestSignerCertificateService.renewRSC("invalidName");
    Assertions.assertTrue(result.isPresent());

    // TermAuthService throws Exception
    Mockito.when(facade.getTerminalPermission(ConfigurationTestHelper.CVC_REF_ID)).thenReturn(new TerminalPermission());
    X509Certificate mockCert = Mockito.mock(X509Certificate.class);
    Mockito.when(facade.getRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, true)).thenReturn(mockCert);
    Mockito.when(facade.getRequestSignerCertificateHolder(ConfigurationTestHelper.CVC_REF_ID)).thenReturn("rscChr");
    Mockito.when(facade.getCurrentRscChrId(Mockito.anyString())).thenReturn(1);
    // Mock calls for pending RSC status. Attention the getPendingRscStatus is called twice. Once as a check whether a
    // pending RSC still exists, once as a check whether to send it. For the first call <null> is returned, for the
    // second call READY_TO_SEND
    Mockito.when(facade.getPendingRscStatus(ConfigurationTestHelper.CVC_REF_ID))
           .thenReturn(null)
           .thenReturn(Status.READY_TO_SEND);
    TermAuthService termAuthService = Mockito.mock(TermAuthService.class);
    Mockito.when(termAuthServiceBean.getTermAuthService(ConfigurationTestHelper.SP_NAME)).thenReturn(termAuthService);
    Mockito.doThrow(new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                               "sendRSCCert returned failure_outer_signature"))
           .when(termAuthService)
           .updateRsc(Mockito.any());
    result = requestSignerCertificateService.renewRSC(ConfigurationTestHelper.SP_NAME);
    Assertions.assertTrue(result.isPresent());
  }

  @Test
  void testSendPendingRsc() throws Exception
  {
    KeyStore ks = KeyStoreSupporter.readKeyStore(RequestSignerCertificateServiceImplTest.class.getResource("/configuration/ec.jks")
                                                                                              .openStream(),
                                                 KeyStoreType.JKS,
                                                 "123456");
    X509Certificate cert = (X509Certificate)ks.getCertificate("ec");
    byte[] key = ks.getKey("ec", "123456".toCharArray()).getEncoded();
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Mockito.when(facade.getRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, true)).thenReturn(cert);
    Mockito.when(facade.getRequestSignerKey(ConfigurationTestHelper.CVC_REF_ID, true)).thenReturn(key);
    Mockito.when(facade.getRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, false)).thenReturn(cert);
    Mockito.when(facade.getPendingRscStatus(ConfigurationTestHelper.CVC_REF_ID)).thenReturn(Status.READY_TO_SEND);
    TermAuthService termAuthService = Mockito.mock(TermAuthService.class);
    Mockito.when(termAuthServiceBean.getTermAuthService(ConfigurationTestHelper.SP_NAME)).thenReturn(termAuthService);
    Optional<String> result = requestSignerCertificateService.sendPendingRSC(ConfigurationTestHelper.SP_NAME);
    Assertions.assertTrue(result.isEmpty());
    Mockito.verify(facade).makePendingRscToCurrentRsc(ConfigurationTestHelper.CVC_REF_ID, true);
  }

  @Test
  void testSendPendingRscFailed() throws Exception
  {
    // TermAuthService throws Exception
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    TermAuthService termAuthService = Mockito.mock(TermAuthService.class);
    Mockito.when(termAuthServiceBean.getTermAuthService(ConfigurationTestHelper.SP_NAME)).thenReturn(termAuthService);
    Mockito.doThrow(new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                               "sendRSCCert returned failure_outer_signature"))
           .when(termAuthService)
           .updateRsc(Mockito.any());
    Optional<String> result = requestSignerCertificateService.sendPendingRSC(ConfigurationTestHelper.SP_NAME);
    Assertions.assertTrue(result.isPresent());
  }

  @Test
  void testDeletePendingRsc() throws Exception
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Optional<String> result = requestSignerCertificateService.deletePendingRSC(ConfigurationTestHelper.SP_NAME);
    Assertions.assertTrue(result.isEmpty());
    Mockito.verify(facade).deletePendingRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID);
    Mockito.verify(facade).setPendingRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, null);
    Mockito.verify(facade).setRequestSignerCertificateHolder(ConfigurationTestHelper.CVC_REF_ID, null);
  }

  @Test
  void testDeletePendingRscWhenCurrentRscPresent() throws Exception
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(prepareConfiguration()));
    Mockito.when(facade.getRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, true))
           .thenReturn(Mockito.mock(X509Certificate.class));
    Optional<String> result = requestSignerCertificateService.deletePendingRSC(ConfigurationTestHelper.SP_NAME);
    Assertions.assertTrue(result.isEmpty());
    Mockito.verify(facade).deletePendingRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID);
    Mockito.verify(facade).setPendingRequestSignerCertificate(ConfigurationTestHelper.CVC_REF_ID, null);
    Mockito.verify(facade, Mockito.never()).setRequestSignerCertificateHolder(ConfigurationTestHelper.CVC_REF_ID, null);

  }

  @SneakyThrows
  EidasMiddlewareConfig prepareConfiguration()
  {
    var configuration = ConfigurationTestHelper.createValidConfiguration();
    configuration.getEidasConfiguration().setCountryCode("DE");
    configuration.getEidasConfiguration().setPublicServiceProviderName(DEFAULT_PROVIDER);
    ServiceProviderType sp = new ServiceProviderType();
    sp.setName(DEFAULT_PROVIDER);
    sp.setCVCRefID(DEFAULT_CVCREFID);
    sp.setEnabled(true);
    configuration.getEidConfiguration().getServiceProvider().add(sp);
    return configuration;
  }
}
