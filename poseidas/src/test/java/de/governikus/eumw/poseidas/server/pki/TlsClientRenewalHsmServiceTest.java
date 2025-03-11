package de.governikus.eumw.poseidas.server.pki;

import static de.governikus.eumw.poseidas.server.pki.TlsClientRenewalDbServiceTest.SERVICE_PROVIDER_NAME;

import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthServiceBean;
import de.governikus.eumw.poseidas.server.pki.repositories.PendingCsrRepository;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.OptionalNoPollBeforeType;
import de.governikus.eumw.utils.key.KeyStoreSupporter;


@ExtendWith(MockitoExtension.class)
class TlsClientRenewalHsmServiceTest
{

  private static final String PENDING_KEY_NAME = "CVCRefID-PendingTLS";

  private static final String CURRENT_KEY_NAME = "CVCRefID";

  @Mock
  ConfigurationService configurationService;

  @Mock
  RequestSignerCertificateService requestSignerCertificateService;

  @Mock
  TermAuthServiceBean termAuthServiceBean;

  @Mock
  PendingCsrRepository pendingCsrRepository;

  @Mock
  HSMService hsmService;

  @Mock
  KeyStore mockedKeyStore;

  Key privateKey;

  Certificate certificate;

  ServiceProviderType serviceProviderType;

  @InjectMocks
  TlsClientRenewalHsmService tlsClientRenewalHsmService;

  @BeforeEach
  void setUp() throws Exception
  {
    // Set mock so that the init method does not try to find an instance for the HSMService
    tlsClientRenewalHsmService.setHsm(hsmService);
    // Prepare Mocks
    byte[] keyStoreBytes = TlsClientRenewalHsmService.class.getResourceAsStream("/keys/dummy-key-for-hsm-test.jks")
                                                           .readAllBytes();
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreBytes, KeyStoreSupporter.KeyStoreType.JKS, "123456");
    certificate = keyStore.getCertificate(PENDING_KEY_NAME);
    PublicKey publicKey = certificate.getPublicKey();
    privateKey = keyStore.getKey(PENDING_KEY_NAME, "123456".toCharArray());
    Mockito.when(mockedKeyStore.getKey(PENDING_KEY_NAME, null)).thenReturn(privateKey);
    Mockito.when(hsmService.getKeyStore()).thenReturn(mockedKeyStore);
    Mockito.when(hsmService.getPublicKey(PENDING_KEY_NAME)).thenReturn(publicKey);

    serviceProviderType = TlsClientRenewalServiceTest.getServiceProviderType();
  }

  @Test
  void testStoreCertificateSuccess() throws Exception
  {
    Mockito.when(hsmService.containsKey(PENDING_KEY_NAME)).thenReturn(Boolean.TRUE);
    EidasMiddlewareConfig eidasMiddlewareConfig = TlsClientRenewalDbServiceTest.getConfiguration();
    ServiceProviderType serviceProviderType = TlsClientRenewalServiceTest.getServiceProviderType();
    byte[] signedCsrCertificateAsByteArray = TlsClientRenewalServiceTest.getSignedCsrCertificateAsByteArray();
    X509Certificate[] x509CertificateArray = {Utils.readCert(signedCsrCertificateAsByteArray)};

    Optional<String> optionalMessage = tlsClientRenewalHsmService.storeCertificate(eidasMiddlewareConfig,
                                                                                   serviceProviderType,
                                                                                   List.of(signedCsrCertificateAsByteArray));

    Assertions.assertTrue(optionalMessage.isEmpty());
    Mockito.verify(mockedKeyStore, Mockito.times(1)).deleteEntry(CURRENT_KEY_NAME);
    Mockito.verify(mockedKeyStore, Mockito.times(1))
           .setKeyEntry(CURRENT_KEY_NAME, privateKey, null, x509CertificateArray);
    Mockito.verify(mockedKeyStore, Mockito.times(1)).deleteEntry(PENDING_KEY_NAME);
  }

  @Test
  void testCheckCert() throws Exception
  {
    Mockito.when(configurationService.getConfiguration())
           .thenReturn(Optional.of(TlsClientRenewalDbServiceTest.getConfiguration()));
    Mockito.when(mockedKeyStore.getCertificate(CURRENT_KEY_NAME)).thenReturn(certificate);
    Mockito.when(mockedKeyStore.getKey(PENDING_KEY_NAME, null)).thenReturn(privateKey);
    Mockito.when(hsmService.containsKey(PENDING_KEY_NAME)).thenReturn(Boolean.TRUE);
    prepareRscServiceAndTerminalAuthMocks();
    // Set deadline 100 years in the future
    Date deadline = new Date(Instant.now().plus(36500, ChronoUnit.DAYS).toEpochMilli());
    tlsClientRenewalHsmService.checkCert(serviceProviderType, deadline);

    Mockito.verify(pendingCsrRepository, Mockito.times(1)).saveAndFlush(Mockito.any());
  }

  @Test
  void testGenerateAndSendCsr() throws Exception
  {
    Mockito.when(configurationService.getConfiguration())
           .thenReturn(Optional.of(TlsClientRenewalDbServiceTest.getConfiguration()));
    Mockito.when(hsmService.containsKey(PENDING_KEY_NAME)).thenReturn(Boolean.TRUE);
    prepareRscServiceAndTerminalAuthMocks();

    Optional<String> optionalMessage = tlsClientRenewalHsmService.generateAndSendCsr(serviceProviderType.getName(),
                                                                                     PENDING_KEY_NAME);
    Assertions.assertTrue(optionalMessage.isEmpty());
    Mockito.verify(pendingCsrRepository, Mockito.times(1)).saveAndFlush(Mockito.any());
  }

  @Test
  void testGenerateAndSendCsrWithNewKey() throws Exception
  {
    Mockito.when(configurationService.getConfiguration())
           .thenReturn(Optional.of(TlsClientRenewalDbServiceTest.getConfiguration()));
    Mockito.when(hsmService.containsKey(PENDING_KEY_NAME)).thenReturn(Boolean.FALSE);
    prepareRscServiceAndTerminalAuthMocks();

    Optional<String> optionalMessage = tlsClientRenewalHsmService.generateAndSendCsrWithNewKey(serviceProviderType.getName());

    Assertions.assertTrue(optionalMessage.isEmpty());

    Mockito.verify(hsmService, Mockito.times(1))
           .generateKeyPair(Mockito.eq("RSA"),
                            Mockito.any(RSAKeyGenParameterSpec.class),
                            Mockito.eq(PENDING_KEY_NAME),
                            Mockito.isNull(),
                            Mockito.eq(Boolean.TRUE),
                            Mockito.eq(360));
    Mockito.verify(pendingCsrRepository, Mockito.times(1)).saveAndFlush(Mockito.any());
  }

  private void prepareRscServiceAndTerminalAuthMocks() throws GovManagementException
  {
    byte[] dummyCsrBytes = ArrayUtils.EMPTY_BYTE_ARRAY;
    Mockito.when(requestSignerCertificateService.signCmsContainer(Mockito.any(), Mockito.any(), Mockito.any()))
           .thenReturn(Optional.of(dummyCsrBytes));
    TermAuthService termAuthService = Mockito.mock(TermAuthService.class);
    Mockito.when(termAuthServiceBean.getTermAuthService(SERVICE_PROVIDER_NAME)).thenReturn(termAuthService);
    OptionalNoPollBeforeType optionalNoPollBeforeType = new OptionalNoPollBeforeType();
    optionalNoPollBeforeType.setNoPollBefore(42000);
    Mockito.when(termAuthService.requestNewTls(Mockito.eq(dummyCsrBytes), Mockito.any()))
           .thenReturn(optionalNoPollBeforeType);
  }
}
