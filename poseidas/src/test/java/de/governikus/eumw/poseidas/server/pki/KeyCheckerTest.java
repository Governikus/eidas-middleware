package de.governikus.eumw.poseidas.server.pki;

import static de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService.KEY_ALGO;
import static de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService.DEFAULT_KEY_SIZE_RSA;
import static de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService.MINIMAL_KEY_SIZE_RSA;
import static org.assertj.core.api.Fail.fail;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.KeyPair;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;



@ExtendWith(MockitoExtension.class)
class KeyCheckerTest
{

  @Mock
  ConfigurationService configurationService;

  @InjectMocks
  KeyChecker keyChecker;

  @Execution(ExecutionMode.CONCURRENT)
  @ParameterizedTest
  @MethodSource("testCases")
  void checkKeyPairValidForTlsClientRenewal(String name,
                                            int keysize,
                                            int daysSinceValid,
                                            int daysUntilInvalid,
                                            boolean valid,
                                            String text)
  {

    if (!"current".equals(name))
    {
      Mockito.when(configurationService.getKeyPair(name))
             .thenReturn(generateKeypair(keysize, daysSinceValid, daysUntilInvalid));
    }

    KeyChecker.MtlsKeyCheck mtlsKeyCheck = keyChecker.checkKeyPairValidForTlsClientRenewal(name, "current");
    Assertions.assertEquals(valid, mtlsKeyCheck.isValid());
    Assertions.assertEquals(text, mtlsKeyCheck.reason());
  }

  public static Stream<Arguments> testCases()
  {
    return Stream.of(arguments("valid-min", MINIMAL_KEY_SIZE_RSA, 1, 1, true, ""),
                     arguments("valid", DEFAULT_KEY_SIZE_RSA, 1, 1, true, ""),
                     arguments("to-short", 1024, 1, 1, false, "key size (1024) is less than 3072 bit"),
                     arguments("not-valid-yet", MINIMAL_KEY_SIZE_RSA, -2, 3, false, "Not valid yet"),
                     arguments("expired", MINIMAL_KEY_SIZE_RSA, -2, -1, false, "expired"),
                     arguments("current", MINIMAL_KEY_SIZE_RSA, 1, 1, false, "current"));
  }


  private KeyPair generateKeypair(int size, int daysSinceValid, int daysUntilInvalid)
  {
    LocalDate start = LocalDate.now().minusDays(daysSinceValid);
    LocalDate end = LocalDate.now().plusDays(daysUntilInvalid);
    try
    {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGO, SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      kpg.initialize(size);
      java.security.KeyPair kp = kpg.generateKeyPair();
      Certificate tempCert = CertificateUtil.createSelfSignedCert(kp.getPublic(),
                                                                  kp.getPrivate(),
                                                                  "CN=DUMMY",
                                                                  Date.from(start.atStartOfDay(ZoneId.systemDefault())
                                                                                 .toInstant()),
                                                                  Date.from(end.atStartOfDay(ZoneId.systemDefault())
                                                                               .toInstant()),
                                                                  SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      String alias = UUID.randomUUID().toString();
      String password = UUID.randomUUID().toString();
      KeyStore keyStore = KeyStoreSupporter.toKeyStore(kp.getPrivate(),
                                                       tempCert,
                                                       alias,
                                                       password,
                                                       KeyStoreSupporter.KeyStoreType.JKS);

      return new KeyPair(keyStore, alias, password);
    }
    catch (Exception e)
    {
      fail("Failed to create certificate.", e);
      return null;
    }
  }
}
