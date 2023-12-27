package de.governikus.eumw.eidasstarterkit;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.SneakyThrows;


class EidasSignerTest
{

  @SneakyThrows
  @ParameterizedTest
  @CsvSource(value = {"/rsa-2048.p12:rsa-2048:Certificate is not valid for that purpose because of reason Certificate with subject CN=rsa-2048 and serial 1702297893 does not meet specified minimum RSA key size of 3072.",
                      "/secp224r1.p12:secp224r1:Certificate is not valid for that purpose because of reason Certificate with subject CN=secp224r1 and serial 691177073619503856166633885441189605629960653141 does not meet specified minimum EC key size of 256.",
                      "/brainpoolP512r1-explicit.p12:brainpoolP512r1:Certificate is not valid for that purpose because of reason Certificate with subject CN=BPR-CSCA, OU=Autent, O=Governikus, L=Bremen, C=DE and serial 30727073461927801660542095644293943332594583035 does not use a named curve."}, delimiter = ':')
  void testInvalidKeys(String keyStorePath, String alias, String expectedErrorMessage)
  {
    InputStream keyStoreInputStream = EidasSignerTest.class.getResourceAsStream(keyStorePath);
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreInputStream,
                                                       KeyStoreSupporter.KeyStoreType.PKCS12,
                                                       "123456");

    IllegalArgumentException illegalArgumentException = Assertions.assertThrows(IllegalArgumentException.class,
                                                                                () -> new EidasSigner((PrivateKey)keyStore.getKey(alias,
                                                                                                                                  "123456".toCharArray()),
                                                                                                      (X509Certificate)keyStore.getCertificate(alias)));
    Assertions.assertEquals(expectedErrorMessage, illegalArgumentException.getCause().getMessage());
  }

  @SneakyThrows
  @ParameterizedTest
  @CsvSource({"/eidassignertest_ec.p12,eumw-test-ec", "/eidassignertest.p12,eidassignertest"})
  void testValidKeys(String keyStorePath, String alias)
  {
    InputStream keyStoreInputStream = EidasSignerTest.class.getResourceAsStream(keyStorePath);
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(keyStoreInputStream,
                                                       KeyStoreSupporter.KeyStoreType.PKCS12,
                                                       "123456");
    Assertions.assertDoesNotThrow(() -> new EidasSigner((PrivateKey)keyStore.getKey(alias, "123456".toCharArray()),
                                                        (X509Certificate)keyStore.getCertificate(alias)));
  }

}
