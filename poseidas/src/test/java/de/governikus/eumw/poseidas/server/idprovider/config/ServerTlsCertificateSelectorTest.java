package de.governikus.eumw.poseidas.server.idprovider.config;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;


class ServerTlsCertificateSelectorTest
{

  static X509Certificate caCertificate;

  static X509Certificate subCaCertificate;

  static X509Certificate serverCertificate;

  static X509Certificate serverCertificateNoChain;

  private final ServerTlsCertificateSelector serverTlsCertificateSelector = new ServerTlsCertificateSelector();


  @BeforeAll
  static void initCerts() throws CertificateException
  {
    caCertificate = (X509Certificate)CertificateFactory.getInstance("X.509")
                                                       .generateCertificate(ServerTlsCertificateSelector.class.getResourceAsStream("/test-tls-certificates/ca.cert"));
    Assertions.assertNotNull(caCertificate);

    subCaCertificate = (X509Certificate)CertificateFactory.getInstance("X.509")
                                                          .generateCertificate(ServerTlsCertificateSelector.class.getResourceAsStream("/test-tls-certificates/sub_ca.cert"));
    Assertions.assertNotNull(subCaCertificate);

    serverCertificate = (X509Certificate)CertificateFactory.getInstance("X.509")
                                                           .generateCertificate(ServerTlsCertificateSelector.class.getResourceAsStream("/test-tls-certificates/server.cert"));
    Assertions.assertNotNull(serverCertificate);

    serverCertificateNoChain = (X509Certificate)CertificateFactory.getInstance("X.509")
                                                                  .generateCertificate(ServerTlsCertificateSelector.class.getResourceAsStream("/test-tls-certificates/server-no-chain.cert"));
    Assertions.assertNotNull(serverCertificateNoChain);
  }

  @Test
  void testValidOrderedChain()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(caCertificate,
                                                                                                                subCaCertificate,
                                                                                                                serverCertificate));
    Assertions.assertTrue(x509Certificate.isPresent());
    Assertions.assertEquals(serverCertificate, x509Certificate.get());
  }

  @Test
  void testValidReversedOrderedChain()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(serverCertificate,
                                                                                                                subCaCertificate,
                                                                                                                caCertificate));
    Assertions.assertTrue(x509Certificate.isPresent());
    Assertions.assertEquals(serverCertificate, x509Certificate.get());
  }

  @Test
  void testValidUnorderedChain()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(subCaCertificate,
                                                                                                                serverCertificate,
                                                                                                                caCertificate));
    Assertions.assertTrue(x509Certificate.isPresent());
    Assertions.assertEquals(serverCertificate, x509Certificate.get());
  }

  @Test
  void testOnlyChainedServerCertificate()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(serverCertificate));
    Assertions.assertTrue(x509Certificate.isPresent());
    Assertions.assertEquals(serverCertificate, x509Certificate.get());
  }

  @Test
  void testStandaloneServerCertificate()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(serverCertificateNoChain));
    Assertions.assertTrue(x509Certificate.isPresent());
    Assertions.assertEquals(serverCertificateNoChain, x509Certificate.get());
  }

  @Test
  void testHalfChain()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(subCaCertificate,
                                                                                                                serverCertificate));
    Assertions.assertTrue(x509Certificate.isPresent());
    Assertions.assertEquals(serverCertificate, x509Certificate.get());
  }

  @Test
  void testNoServerCert()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(subCaCertificate,
                                                                                                                caCertificate));
    Assertions.assertFalse(x509Certificate.isPresent());
  }

  @Test
  void testMultipleServerCert()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of(serverCertificate,
                                                                                                                serverCertificateNoChain));
    Assertions.assertFalse(x509Certificate.isPresent());
  }

  @Test
  void testNoCertificates()
  {
    Optional<X509Certificate> x509Certificate = serverTlsCertificateSelector.selectServerTlsCertificate(List.of());
    Assertions.assertFalse(x509Certificate.isPresent());
  }
}
