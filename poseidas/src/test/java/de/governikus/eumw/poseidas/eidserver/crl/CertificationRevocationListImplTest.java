/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.crl;

import java.security.Principal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import de.governikus.eumw.poseidas.eidserver.crl.exception.CertificateValidationException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;
import de.governikus.eumw.utils.key.SecurityProvider;


@DisplayName("The CertificationRevocationListImpl")
class CertificationRevocationListImplTest
{

  private static CertificateFactory cf;

  private static X509Certificate testCertificate;

  private static Set<X509Certificate> masterList;

  private static ConfigurationService configurationService;

  @BeforeAll
  public static void setUp() throws Exception
  {
    cf = CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    testCertificate = (X509Certificate)cf.generateCertificate(CertificationRevocationListImplTest.class.getResourceAsStream("/DE_TEST_CSCA_2018_12.cer"));
    masterList = new HashSet<>();
    masterList.add(testCertificate);
    configurationService = Mockito.mock(ConfigurationService.class);
  }

  @AfterEach
  public void afterEach()
  {
    CertificationRevocationListImpl.reset();
  }

  @Test
  @DisplayName("has CRL in cache when CRL validation was successful")
  void crlInCacheWhenValidationSuccessful() throws Exception
  {
    CertificationRevocationListImpl.initialize(masterList,
                                               testCertificate,
                                               getCrlFetcher(testCertificate),
                                               configurationService);
    CertificationRevocationListImpl certificationRevocationListImpl = CertificationRevocationListImpl.getInstance();
    List<String> urls = CertificationRevocationListImpl.getCrlDistributionPoints(testCertificate);
    Assertions.assertEquals(1, urls.size());
    X509CRL x509CRL = certificationRevocationListImpl.getX509CRL(urls.get(0));

    int version = x509CRL.getVersion();
    Principal issuerDN = x509CRL.getIssuerDN();
    String name = issuerDN.getName();
    Assertions.assertEquals("C=DE,O=bund,OU=bsi,CN=TEST csca-germany", name);
    Assertions.assertEquals(2, version);
  }

  @Test
  @DisplayName("throws exception when the signature certificate is false")
  void crlThrowsAnExceptionWhenSignatureCertificateIsFalse() throws Exception
  {
    X509Certificate certificate = (X509Certificate)cf.generateCertificate(CertificationRevocationListImplTest.class.getResourceAsStream("/csca-root-cert.cer"));
    Set<X509Certificate> masterList = new HashSet<>();
    masterList.add(certificate);
    CrlFetcher fetcher = getCrlFetcher(certificate);
    IllegalStateException illegalStateException = Assertions.assertThrows(IllegalStateException.class,
                                                                          () -> CertificationRevocationListImpl.initialize(masterList,
                                                                                                                           certificate,
                                                                                                                           fetcher,
                                                                                                                           configurationService));

    Assertions.assertEquals("Exception during initial retrieval of CRL", illegalStateException.getMessage());
    Throwable certificateValidationException = illegalStateException.getCause();
    Assertions.assertTrue(certificateValidationException instanceof CertificateValidationException);
    Assertions.assertEquals("Could not verify CRL", certificateValidationException.getMessage());
  }

  @Test
  @DisplayName("url is read from the certificate")
  void crlUrlIsUrlFromCredential()
  {
    List<String> urls = CertificationRevocationListImpl.getCrlDistributionPoints(testCertificate);
    Assertions.assertEquals(1, urls.size());
    Assertions.assertEquals("http://www.bsi.bund.de/test_csca_crl", urls.get(0));
  }

  @Test
  @DisplayName("url is empty when a certificate has no distribution points")
  void crlUrlIsEmptyWhenCertificateHasNoDistributionPoints() throws Exception
  {
    X509Certificate certificate = (X509Certificate)cf.generateCertificate(CertificationRevocationListImpl.class.getResourceAsStream("/wrong-signature-cert.cer"));
    List<String> urls = CertificationRevocationListImpl.getCrlDistributionPoints(certificate);

    Assertions.assertTrue(urls.isEmpty());
  }

  @Test
  @DisplayName("does not contain the given certificate")
  void isNotOnCrlTest()
  {
    Set<X509Certificate> masterList = new HashSet<>();
    masterList.add(testCertificate);
    CertificationRevocationListImpl.initialize(masterList,
                                               testCertificate,
                                               getCrlFetcher(testCertificate),
                                               configurationService);
    CertificationRevocationListImpl certificationRevocationList = CertificationRevocationListImpl.getInstance();
    Assertions.assertFalse(certificationRevocationList.isOnCRL(testCertificate));
  }

  @Test
  @DisplayName("contains an intermediate certificate")
  void isOnCrlTest() throws Exception
  {
    // Root Certificate
    X509Certificate caCertificate = (X509Certificate)cf.generateCertificate(CertificationRevocationListImplTest.class.getResourceAsStream("/ca.crt"));
    // Document Signer
    X509Certificate iaCertificate = (X509Certificate)cf.generateCertificate(CertificationRevocationListImplTest.class.getResourceAsStream("/ia.crt"));
    Set<X509Certificate> masterList = new HashSet<>();
    masterList.add(caCertificate);
    CertificationRevocationListImpl.initialize(masterList,
                                               caCertificate,
                                               getCrlFetcher(caCertificate),
                                               configurationService);
    CertificationRevocationListImpl certificationRevocationList = CertificationRevocationListImpl.getInstance();
    Assertions.assertTrue(certificationRevocationList.isOnCRL(iaCertificate));
  }

  @Test
  @DisplayName("is initialized when certificate is null and crlFetcher is mocked")
  void whenGetInstanceCalledThenReturnInstanceCertificationListImpl() throws Exception
  {
    Mockito.when(configurationService.getConfiguration())
           .thenReturn(Optional.of(ConfigurationTestHelper.createValidConfiguration()));
    CertificationRevocationListImpl.initialize(masterList, null, getCrlFetcher(testCertificate), configurationService);
    CertificationRevocationListImpl instance = CertificationRevocationListImpl.getInstance();

    Assertions.assertNotNull(instance);
    System.clearProperty("spring.config.additional-location");
  }

  @Test
  @DisplayName("throws an IllegalStateException when getInstance is called before calling an initialize method")
  void throwsIllegalStateExceptionWhenGetInstanceIsCalledBeforeInitialize()
  {
    IllegalStateException illegalStateException = Assertions.assertThrows(IllegalStateException.class,
                                                                          CertificationRevocationListImpl::getInstance);
    Assertions.assertEquals("Class is not initialized", illegalStateException.getMessage());
  }

  @Test
  @DisplayName("throws an IllegalStateException when initialize is called more than once")
  void throwsIllegalStateExceptionWhenInitializeIsCalledTwice()
  {
    CertificationRevocationListImpl.initialize(masterList,
                                               testCertificate,
                                               getCrlFetcher(testCertificate),
                                               configurationService);
    CertificationRevocationListImpl instance = CertificationRevocationListImpl.getInstance();

    Assertions.assertNotNull(instance);
    Assertions.assertThrows(IllegalStateException.class,
                            () -> CertificationRevocationListImpl.initialize(masterList, configurationService));
  }

  @Test
  @DisplayName("cache contains a new CrlDAO after calling renew Crls")
  void crlCacheContainsNewCrlDAOAfterRenewal()
  {
    CertificationRevocationListImpl.initialize(masterList,
                                               testCertificate,
                                               getCrlFetcher(testCertificate),
                                               configurationService);
    CertificationRevocationListImpl instance = CertificationRevocationListImpl.getInstance();
    CrlCache crlCache = instance.getCrlCache();
    Set<String> availableUrls = crlCache.getAvailableUrls();
    List<CrlDao> crls = availableUrls.stream().map(crlCache::get).collect(Collectors.toList());
    Assertions.assertEquals(1, crls.size());
    CrlDao crlDao = crls.get(0);
    long lastUpdate = crlDao.getLastUpdate();

    instance.renewCrls();
    availableUrls.forEach(url -> Assertions.assertNotNull(crlCache.get(url)));
    List<CrlDao> renewCrls = availableUrls.stream().map(crlCache::get).collect(Collectors.toList());
    Assertions.assertEquals(1, renewCrls.size());
    CrlDao renewCrlDao = renewCrls.get(0);
    long lastUpdateRenew = renewCrlDao.getLastUpdate();

    Assertions.assertNotEquals(lastUpdateRenew, lastUpdate);
  }

  @Test
  @DisplayName("returns null when no CRL is cached and no CRL can be downloaded")
  void returnsNoCRLWhenUrlNoCachedAndDownloadCRLAvailable()
  {
    CertificationRevocationListImpl.initialize(masterList,
                                               testCertificate,
                                               getCrlFetcher(testCertificate),
                                               configurationService);
    CertificationRevocationListImpl instance = CertificationRevocationListImpl.getInstance();
    X509CRL x509CRL = instance.getX509CRL("mock-address");

    Assertions.assertNull(x509CRL);
  }

  /**
   * returns a {@link HttpCrlFetcher} that overwrites the httpDownload method for test purposes.
   *
   * @param certificate to verify the signature of the CRL
   * @return CacheCrlFetcher
   */
  private HttpCrlFetcher getCrlFetcher(X509Certificate certificate)
  {
    Set<X509Certificate> trustSet = new HashSet<>();
    trustSet.add(certificate);
    return new HttpCrlFetcher(trustSet)
    {

      @Override
      protected X509CRL httpDownload(String url) throws CertificateValidationException
      {
        try
        {
          CertificateFactory cf = CertificateFactory.getInstance("X509",
                                                                 SecurityProvider.BOUNCY_CASTLE_PROVIDER);
          if ("http://example.com/root.crl".equalsIgnoreCase(url))
          {
            return (X509CRL)cf.generateCRL(CertificationRevocationListImplTest.class.getResourceAsStream("/root.crl"));
          }
          else
          {
            return (X509CRL)cf.generateCRL(CertificationRevocationListImplTest.class.getResourceAsStream("/TEST.crl"));
          }
        }
        catch (Exception e)
        {
          throw new CertificateValidationException("For Test purpose");
        }
      }
    };
  }
}
