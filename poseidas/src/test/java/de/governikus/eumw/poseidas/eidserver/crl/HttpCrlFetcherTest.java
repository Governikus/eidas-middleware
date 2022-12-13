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

import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import de.governikus.eumw.poseidas.eidserver.crl.exception.CertificateValidationException;
import de.governikus.eumw.utils.key.SecurityProvider;


@DisplayName("The HttpCrlFetcher")
class HttpCrlFetcherTest
{

  private static final String HTTP_TEST_URL = "http://testUrl.de";

  private X509Certificate certificate;

  private CertificateFactory cf;

  @BeforeEach
  void setUp() throws Exception
  {
    cf = CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    certificate = (X509Certificate)cf.generateCertificate(CertificationRevocationListImplTest.class.getResourceAsStream("/DE_TEST_CSCA_2018_12.cer"));
  }

  @Test
  @DisplayName("returns the downloaded crl on successful CRL signature validation")
  void returnCrlOnSuccessfulValidation() throws Exception
  {
    HttpCrlFetcher crlFetcher = getCrlFetcher(certificate);
    X509CRL x509CRL = crlFetcher.download(HTTP_TEST_URL);

    Assertions.assertEquals("C=DE,O=bund,OU=bsi,CN=TEST csca-germany", x509CRL.getIssuerDN().getName());
    Assertions.assertEquals(2, x509CRL.getVersion());
  }

  @Test
  @DisplayName("returns null when the url is malformed")
  void crlFetcherReturnsNullWhenUrlMalformed() throws Exception
  {
    Set<X509Certificate> trustSet = new HashSet<>();
    trustSet.add(certificate);
    HttpCrlFetcher crlFetcher = new HttpCrlFetcher(trustSet);
    X509CRL x509CRL = crlFetcher.download("malformedUrl");

    Assertions.assertNull(x509CRL);
  }

  @Test
  @DisplayName("returns null when the url is null")
  void crlFetcherReturnsNullWhenUrlIsNull() throws Exception
  {
    Set<X509Certificate> trustSet = new HashSet<>();
    trustSet.add(certificate);
    HttpCrlFetcher crlFetcher = new HttpCrlFetcher(trustSet);
    X509CRL x509CRL = crlFetcher.download(null);

    Assertions.assertNull(x509CRL);
  }

  @Test
  @DisplayName("throws a CertificateValidationException when the signature cannot be validated")
  void crlFetcherThrowsCertValidationExceptionWhitFalseCertificate() throws Exception
  {
    X509Certificate certificate = (X509Certificate)cf.generateCertificate(CertificationRevocationListImplTest.class.getResourceAsStream("/wrong-signature-cert.cer"));
    HttpCrlFetcher crlFetcher = getCrlFetcher(certificate);

    CertificateValidationException certificateValidationException = Assertions.assertThrows(CertificateValidationException.class,
                                                                                            () -> crlFetcher.download(HTTP_TEST_URL));

    Assertions.assertEquals("Could not verify CRL", certificateValidationException.getMessage());
  }

  /**
   * returns a {@link HttpCrlFetcher} that overwrites the httpDownload method for test purposes.
   *
   * @param certificate to verify the signature of the CRL
   * @return CacheCrlFetcher
   * @throws Exception
   */
  private HttpCrlFetcher getCrlFetcher(X509Certificate certificate) throws Exception
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
          return (X509CRL)cf.generateCRL(CertificationRevocationListImplTest.class.getResourceAsStream("/TEST.crl"));
        }
        catch (Exception e)
        {
          throw new CertificateValidationException("For Test purpose");
        }
      }
    };
  }
}
