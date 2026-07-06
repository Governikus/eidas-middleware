package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.io.File;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;


class PKIServiceConnectorTest
{

  private static final String DUMMY_PASSWORD = "123456";

  @Test
  void testSslContextWithDvcaServerCertificate() throws Exception
  {

    X509Certificate serverCert = getDvcaServerCert();

    KeyStore keyStore = getClientKeyStore();

    PKIServiceConnector pkiServiceConnector = new PKIServiceConnector(42, serverCert, keyStore,
                                                                      DUMMY_PASSWORD.toCharArray(), "entityID");
    Assertions.assertDoesNotThrow(pkiServiceConnector::createSSLContext);
  }

  @Test
  void testSslContextNoDvcaServerCertificate() throws Exception
  {
    KeyStore keyStore = getClientKeyStore();

    PKIServiceConnector pkiServiceConnector = new PKIServiceConnector(42, null, keyStore, DUMMY_PASSWORD.toCharArray(),
                                                                      "entityID");
    Assertions.assertDoesNotThrow(pkiServiceConnector::createSSLContext);
  }

  private static X509Certificate getDvcaServerCert() throws CertificateException
  {
    CertificateFactory cf = CertificateFactory.getInstance("X509", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    return (X509Certificate)cf.generateCertificate(PKIServiceConnectorTest.class.getResourceAsStream("/test-tls-certificates/server.cert"));
  }

  private static @NonNull KeyStore getClientKeyStore() throws URISyntaxException
  {
    File keystoreFile = new File(PKIServiceConnectorTest.class.getResource("/keys/bos-test-tctoken.saml-sign.p12")
                                                              .toURI());
    return KeyStoreSupporter.readKeyStore(keystoreFile, DUMMY_PASSWORD);
  }
}
