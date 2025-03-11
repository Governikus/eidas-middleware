package de.governikus.eumw.poseidas.server.pki;

import static de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService.KEY_ALGO;
import static de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService.MINIMAL_KEY_SIZE_RSA;

import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.springframework.stereotype.Service;

import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * A checker for keys that can be used in teh frontend
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class KeyChecker
{

  private final ConfigurationService configurationService;

  /**
   * Checks if a key meets the requirements to be used as a new tls client key
   * 
   * @param keyPairName the name of the key pair to check
   * @param currentTlsClientKeypair the name of the current tls client key pair of the service provider
   * @return an object containing a boolean and a message in case of a key not matching the requirements
   */
  public MtlsKeyCheck checkKeyPairValidForTlsClientRenewal(String keyPairName, String currentTlsClientKeypair)
  {

    if (keyPairName.equalsIgnoreCase(currentTlsClientKeypair))
    {
      return new MtlsKeyCheck(false, "current");
    }

    X509Certificate certificate;
    try
    {
      var keyPair = configurationService.getKeyPair(keyPairName);
      // Check validity
      certificate = keyPair.getCertificate();
      certificate.checkValidity();
    }
    catch (CertificateNotYetValidException e)
    {
      log.debug("Keypair cannot be used for tls client key renewal {}", keyPairName, e);
      return new MtlsKeyCheck(false, "Not valid yet");
    }
    catch (CertificateExpiredException e)
    {
      log.debug("Keypair cannot be used for tls client key renewal {}", keyPairName, e);
      return new MtlsKeyCheck(false, "expired");
    }
    catch (Exception e)
    {
      log.warn("Error while checking key pair {}", keyPairName, e);
      return new MtlsKeyCheck(true, "not checked!"); // Set true on error to be failsafe
    }

    PublicKey publicKey = certificate.getPublicKey();

    if (!KEY_ALGO.equalsIgnoreCase(publicKey.getAlgorithm()))
    {
      log.debug("Keypair cannot be used for tls client key renewal {}. Not RSA.", keyPairName);
      return new MtlsKeyCheck(false, "Not an RSA key");
    }

    int keySize = ((RSAPublicKey)publicKey).getModulus().bitLength();
    if (keySize < MINIMAL_KEY_SIZE_RSA)
    {
      log.debug("Keypair cannot be used for tls client key renewal {}. Key size is less than {} bit",
                keyPairName,
                MINIMAL_KEY_SIZE_RSA);
      return new MtlsKeyCheck(false, "key size (%s) is less than %s bit".formatted(keySize, MINIMAL_KEY_SIZE_RSA));
    }

    log.debug("Keypair {} is valid for tls client key renewal.", keyPairName);
    return new MtlsKeyCheck(true, "");
  }

  public record MtlsKeyCheck(boolean isValid, String reason) {
  }

}
