package de.governikus.eumw.poseidas.server.pki;

import static de.governikus.eumw.poseidas.server.pki.TlsClientRenewalServiceTest.DUMMY_KEY_PAIR_NAME;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.server.idprovider.config.Configuration;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationRepository;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.KeyPair;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthServiceBean;
import de.governikus.eumw.poseidas.server.pki.repositories.PendingCsrRepository;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.OptionalNoPollBeforeType;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.xml.XmlHelper;


@ExtendWith(MockitoExtension.class)
class TlsClientRenewalDbServiceTest
{

  public static final String SERVICE_PROVIDER_NAME = "testsp";

  private static final String CURRENT_CLIENT_KEY_NAME = "currentClientKey";

  private static final String DUMMY_PASSWORD = "123456";

  private static final String DUMMY_KEY_STORE_NAME = "dummy-key-store";

  // This key was used to create a CSR and the public key from this key store can be used to verify the signed
  // certificate SIGNED_CSR_CERTIFICATE
  private static final String DUMMY_KEY_JKS = "/keys/dummy-key.jks";

  @Mock
  ConfigurationRepository configurationRepository;

  @Mock
  RequestSignerCertificateService requestSignerCertificateService;

  @Mock
  TermAuthServiceBean termAuthServiceBean;

  @Mock
  PendingCsrRepository pendingCsrRepository;

  @Mock
  ConfigurationService configurationServiceMock;

  @InjectMocks
  TlsClientRenewalDbService tlsClientRenewalDbService;

  @Test
  void generateAndStoreKeyPair() throws Exception
  {
    // Mock config
    EidasMiddlewareConfig eidasMiddlewareConfig = Mockito.mock(EidasMiddlewareConfig.class);
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = Mockito.mock(EidasMiddlewareConfig.EidConfiguration.class);
    ServiceProviderType serviceProviderType = Mockito.mock(ServiceProviderType.class);
    Mockito.when(serviceProviderType.getName()).thenReturn(SERVICE_PROVIDER_NAME);

    Mockito.when(eidConfiguration.getServiceProvider()).thenReturn(List.of(serviceProviderType));
    Mockito.when(eidasMiddlewareConfig.getEidConfiguration()).thenReturn(eidConfiguration);
    Mockito.when(configurationServiceMock.getConfiguration()).thenReturn(Optional.of(eidasMiddlewareConfig));

    // Generate keypair
    tlsClientRenewalDbService.generateAndStoreKeyPair(SERVICE_PROVIDER_NAME);

    // Capture stored key pair
    ArgumentCaptor<EidasMiddlewareConfig.KeyData> configCaptor = ArgumentCaptor.forClass(EidasMiddlewareConfig.KeyData.class);
    Mockito.verify(eidasMiddlewareConfig, Mockito.times(1)).setKeyData(configCaptor.capture());

    EidasMiddlewareConfig.KeyData storedKeyData = configCaptor.getValue();

    KeyStoreType storedKeyStoreType = storedKeyData.getKeyStore().get(0);
    KeyStore parsedKeyStore = KeyStoreSupporter.readKeyStore(storedKeyStoreType.getKeyStore(),
                                                             KeyStoreSupporter.KeyStoreType.valueOf(storedKeyStoreType.getType()
                                                                                                                      .value()),
                                                             storedKeyStoreType.getPassword());

    // Check key pair
    String keyPairAlias = storedKeyData.getKeyPair().get(0).getAlias();
    X509Certificate certificate = (X509Certificate)parsedKeyStore.getCertificate(keyPairAlias);

    Assertions.assertEquals("RSA", certificate.getPublicKey().getAlgorithm());
    Assertions.assertEquals(4096, ((RSAPublicKey)(certificate.getPublicKey())).getModulus().bitLength());
  }

  @Test
  void testStoreCertificateSuccess() throws Exception
  {
    ServiceProviderType serviceProviderType = new ServiceProviderType();
    serviceProviderType.setName(SERVICE_PROVIDER_NAME);
    serviceProviderType.setPendingClientKeyPairName(DUMMY_KEY_PAIR_NAME);

    EidasMiddlewareConfig eidasMiddlewareConfig = getConfiguration();
    Configuration configuration = new Configuration();
    configuration.setXmlConfigBlob(XmlHelper.marshalObject(eidasMiddlewareConfig).getBytes(StandardCharsets.UTF_8));
    Mockito.when(configurationRepository.findById(1L)).thenReturn(Optional.of(configuration));
    Mockito.when(configurationRepository.save(Mockito.any(Configuration.class))).thenReturn(configuration);

    byte[] csrCertificateAsByteArray = TlsClientRenewalServiceTest.getSignedCsrCertificateAsByteArray();

    List<byte[]> certificates = new ArrayList<>();
    certificates.add(csrCertificateAsByteArray);

    TimerHistoryService timerHistoryServiceMock = Mockito.mock(TimerHistoryService.class);
    ConfigurationService configurationService = new ConfigurationService(configurationRepository);

    tlsClientRenewalDbService = new TlsClientRenewalDbService(configurationService, requestSignerCertificateService,
                                                              pendingCsrRepository, termAuthServiceBean,
                                                              timerHistoryServiceMock);

    Optional<String> optionalMessage = tlsClientRenewalDbService.storeCertificate(eidasMiddlewareConfig,
                                                                                  serviceProviderType,
                                                                                  certificates);
    Assertions.assertTrue(optionalMessage.isEmpty());
  }

  @Test
  void testStoreCertificateWhenNoKeyPresentToCheckCertificate() throws Exception
  {
    ServiceProviderType serviceProviderType = new ServiceProviderType();
    serviceProviderType.setName(SERVICE_PROVIDER_NAME);
    serviceProviderType.setPendingClientKeyPairName("no-key-entry-present");

    Mockito.when(configurationServiceMock.getKeyPair("no-key-entry-present")).thenThrow(ConfigurationException.class);

    Optional<String> optionalMessage = tlsClientRenewalDbService.storeCertificate(getConfiguration(),
                                                                                  serviceProviderType,
                                                                                  Collections.emptyList());

    Assertions.assertTrue(optionalMessage.isPresent());
    Assertions.assertEquals("Key pair not found", optionalMessage.get());
  }

  @Test
  void testCheckCertWithDeadlineReached() throws Exception
  {
    // Mock configurationService but use an instance of EidasMiddlewareConfiguration to use the ArgumentCaptor
    Mockito.when(configurationServiceMock.getConfiguration()).thenReturn(Optional.of(getConfiguration()));

    // Mock current key pair which will be checked
    KeyPair keyPair = getKeyPair();
    Mockito.when(configurationServiceMock.getKeyPair(DUMMY_KEY_PAIR_NAME)).thenReturn(keyPair);

    // Mock RSC Service and TerminalAuthService
    prepareRscServiceAndTerminalAuthMocks();

    // Set deadline 100 years in the future
    Date deadline = new Date(Instant.now().plus(36500, ChronoUnit.DAYS).toEpochMilli());

    // Actual method to test
    tlsClientRenewalDbService.checkCert(TlsClientRenewalServiceTest.getServiceProviderType(), deadline);

    // Capture configuration to verify that a new key was generated and saved as pending key in the configuration
    ArgumentCaptor<EidasMiddlewareConfig> argumentCaptor = ArgumentCaptor.forClass(EidasMiddlewareConfig.class);
    Mockito.verify(configurationServiceMock, Mockito.times(1))
           .saveConfiguration(argumentCaptor.capture(), Mockito.eq(false));
    EidasMiddlewareConfig capturedEidasMiddlewareConfig = argumentCaptor.getValue();
    ServiceProviderType serviceProviderCaptured = capturedEidasMiddlewareConfig.getEidConfiguration()
                                                                               .getServiceProvider()
                                                                               .get(0);
    Assertions.assertNotNull(serviceProviderCaptured.getPendingClientKeyPairName());
    Mockito.verify(pendingCsrRepository, Mockito.times(1)).saveAndFlush(Mockito.any());
  }

  @Test
  void testGenerateAndSendCsr() throws Exception
  {
    // Pepare SP to use different client key pair
    EidasMiddlewareConfig eidasMiddlewareConfig = getConfiguration();
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = eidasMiddlewareConfig.getEidConfiguration();
    ServiceProviderType serviceProviderType = eidConfiguration.getServiceProvider().get(0);
    serviceProviderType.setClientKeyPairName(CURRENT_CLIENT_KEY_NAME);
    eidConfiguration.getServiceProvider().set(0, serviceProviderType);
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);

    // Mock configurationService but use an instance of EidasMiddlewareConfiguration to use the ArgumentCaptor
    Mockito.when(configurationServiceMock.getConfiguration()).thenReturn(Optional.of(eidasMiddlewareConfig));


    // Mock current key pair which will be checked
    KeyPair keyPair = getKeyPair();
    Mockito.when(configurationServiceMock.getKeyPair(DUMMY_KEY_PAIR_NAME)).thenReturn(keyPair);

    // Mock RSC Service and TerminalAuthService
    prepareRscServiceAndTerminalAuthMocks();

    Optional<String> optionalMessage = tlsClientRenewalDbService.generateAndSendCsr(SERVICE_PROVIDER_NAME,
                                                                                    DUMMY_KEY_PAIR_NAME);
    // Capture configuration to verify that a new key was generated and saved as pending key in the configuration
    ArgumentCaptor<EidasMiddlewareConfig> argumentCaptor = ArgumentCaptor.forClass(EidasMiddlewareConfig.class);
    Mockito.verify(configurationServiceMock, Mockito.times(1))
           .saveConfiguration(argumentCaptor.capture(), Mockito.eq(false));
    EidasMiddlewareConfig capturedEidasMiddlewareConfig = argumentCaptor.getValue();
    ServiceProviderType serviceProviderCaptured = capturedEidasMiddlewareConfig.getEidConfiguration()
                                                                               .getServiceProvider()
                                                                               .get(0);
    Assertions.assertNotNull(serviceProviderCaptured.getPendingClientKeyPairName());
    Assertions.assertTrue(optionalMessage.isEmpty());
    Mockito.verify(pendingCsrRepository, Mockito.times(1)).saveAndFlush(Mockito.any());
  }

  @Test
  void testGenerateAndSendCsrWithNewKey() throws Exception
  {
    // Mock configurationService but use an instance of EidasMiddlewareConfiguration to use the ArgumentCaptor
    Mockito.when(configurationServiceMock.getConfiguration()).thenReturn(Optional.of(getConfiguration()));

    // Mock RSC Service and TerminalAuthService
    prepareRscServiceAndTerminalAuthMocks();

    Optional<String> optionalMessage = tlsClientRenewalDbService.generateAndSendCsrWithNewKey(SERVICE_PROVIDER_NAME);
    // Capture configuration to verify that a new key was generated and saved as pending key in the configuration
    ArgumentCaptor<EidasMiddlewareConfig> argumentCaptor = ArgumentCaptor.forClass(EidasMiddlewareConfig.class);
    Mockito.verify(configurationServiceMock, Mockito.times(1))
           .saveConfiguration(argumentCaptor.capture(), Mockito.eq(false));
    Assertions.assertTrue(optionalMessage.isEmpty());
    EidasMiddlewareConfig capturedEidasMiddlewareConfig = argumentCaptor.getValue();
    ServiceProviderType serviceProviderCaptured = capturedEidasMiddlewareConfig.getEidConfiguration()
                                                                               .getServiceProvider()
                                                                               .get(0);
    Assertions.assertNotNull(serviceProviderCaptured.getPendingClientKeyPairName());
    Mockito.verify(pendingCsrRepository, Mockito.times(1)).saveAndFlush(Mockito.any());
  }

  @Test
  void testCurrentTlsCertValidUntil() throws Exception
  {
    Mockito.when(configurationServiceMock.getConfiguration()).thenReturn(Optional.of(getConfiguration()));

    // Prepare the key pair which will be checked
    KeyPair keyPair = getKeyPair();
    Mockito.when(configurationServiceMock.getKeyPair(DUMMY_KEY_PAIR_NAME)).thenReturn(keyPair);

    Optional<Date> optionalExpirationDate = tlsClientRenewalDbService.currentTlsCertValidUntil(SERVICE_PROVIDER_NAME);
    Assertions.assertTrue(optionalExpirationDate.isPresent());
    Date expirationDate = optionalExpirationDate.get();
    Assertions.assertEquals(new Date(2002357262000L), expirationDate);
  }

  public static EidasMiddlewareConfig getConfiguration() throws Exception
  {
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    ServiceProviderType serviceProviderType = TlsClientRenewalServiceTest.getServiceProviderType();
    eidConfiguration.getServiceProvider().add(serviceProviderType);
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setCountryCode("IT");
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);
    eidasMiddlewareConfig.setKeyData(getKeyData());
    return eidasMiddlewareConfig;
  }

  private static EidasMiddlewareConfig.KeyData getKeyData() throws IOException
  {
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    KeyStoreType keyStoreType = getKeyStoreType();
    keyData.getKeyStore().add(keyStoreType);
    KeyPairType keyPairType = getKeyPairType();
    keyData.getKeyPair().add(keyPairType);
    return keyData;
  }

  private static KeyStoreType getKeyStoreType() throws IOException
  {
    KeyStoreType keyStoreType = new KeyStoreType();
    byte[] keyStore = TlsClientRenewalDbServiceTest.class.getResourceAsStream(DUMMY_KEY_JKS).readAllBytes();
    keyStoreType.setKeyStore(keyStore);
    keyStoreType.setType(KeyStoreTypeType.JKS);
    keyStoreType.setPassword(DUMMY_PASSWORD);
    keyStoreType.setName(DUMMY_KEY_STORE_NAME);
    return keyStoreType;
  }

  private static KeyPairType getKeyPairType()
  {
    KeyPairType keyPairType = new KeyPairType();
    keyPairType.setKeyStoreName(DUMMY_KEY_STORE_NAME);
    keyPairType.setPassword(DUMMY_PASSWORD);
    keyPairType.setName(DUMMY_KEY_PAIR_NAME);
    keyPairType.setAlias("dummy-key");
    return keyPairType;
  }

  private static KeyPair getKeyPair() throws IOException
  {
    KeyStoreType keyStoreType = getKeyStoreType();
    KeyPairType keyPairType = getKeyPairType();
    return new KeyPair(KeyStoreSupporter.readKeyStore(keyStoreType.getKeyStore(),
                                                      KeyStoreSupporter.KeyStoreType.valueOf(keyStoreType.getType()
                                                                                                         .value()),
                                                      keyStoreType.getPassword()),
                       keyPairType.getAlias(), keyPairType.getPassword());
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
