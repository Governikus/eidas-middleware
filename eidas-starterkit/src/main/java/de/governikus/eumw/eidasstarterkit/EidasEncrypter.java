/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.agreement.KeyAgreementException;
import org.opensaml.xmlsec.agreement.KeyAgreementParameter;
import org.opensaml.xmlsec.agreement.KeyAgreementParameters;
import org.opensaml.xmlsec.agreement.KeyAgreementSupport;
import org.opensaml.xmlsec.agreement.impl.KANonce;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.derivation.impl.ConcatKDF;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.KeyAgreementKeyInfoGeneratorFactory;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.component.ComponentInitializationException;


@Slf4j
public class EidasEncrypter
{

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.1 and BSI TR-03116-4 (v2025) chapter 3.4.1
   */
  static final String DEFAULT_ALGO_CONTENTENCRYPTION = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM;

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.2 and BSI TR-03116-4 (v2025) chapter 3.4.2.2
   */
  static final String DEFAULT_ALGO_KEYAGREEMENT = EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES;

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.1 and BSI TR-03116-4 (v2025) chapter 3.4.2.1
   */
  public static final String DEFAULT_ALGO_KEYTRANSPORT = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11;

  static final String DEFAULT_ALGO_KEYTRANSPORT_DIGEST = EncryptionConstants.ALGO_ID_DIGEST_SHA256;

  static final String DEFAULT_ALGO_KEYTRANSPORT_MGF = EncryptionConstants.ALGO_ID_MGF1_SHA256;

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.2 and BSI TR-03116-4 (v2025) chapter 3.4.2.2
   */
  static final String DEFAULT_ALGO_KEYWRAP = EncryptionConstants.ALGO_ID_KEYWRAP_AES256;

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.1 and BSI TR-03116-4 (v2025) chapter 3.4.2.1
   */
  private static final int MINIMAL_LENGTH_RSA = 3072;

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.2 and BSI TR-03116-4 (v2025) chapter 3.4.2.2
   */
  private static final int MINIMAL_LENGTH_EC = 256;

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.1.1
   */
  private static final Collection<String> ALLOWED_HASH_FUNCTIONS = Set.of(EncryptionConstants.ALGO_ID_DIGEST_SHA256);

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.1
   */
  private static final Collection<String> ALLOWED_CONTENT_ENCRYPTION_ALGORITHMS = Set.of(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
                                                                                         EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
                                                                                         EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192_GCM);


  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.1
   */
  private static final Collection<String> ALLOWED_KEY_TRANSPORT_ALGORITHMS = Set.of(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11);

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.2
   */
  private static final Map<String, Integer> ALLOWED_KEY_AGREEMENT_ALGORITHMS_AND_MIN_KEY_LENGTH = Map.of(EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                                                                                                         256);


  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.2
   */
  private static final Map<String, Integer> ALLOWED_KEY_WRAPPING_ALGORITHMS_AND_MIN_KEY_LENGTH = Map.of(EncryptionConstants.ALGO_ID_KEYWRAP_AES128,
                                                                                                        128,
                                                                                                        EncryptionConstants.ALGO_ID_KEYWRAP_AES256,
                                                                                                        256);




  /**
   * Completely configured encryption handler, null if encryption is not set.
   */
  @Getter
  private final Encrypter encrypter;


  /**
   * Create a XMLCipher Object.
   *
   * @param includeCert if true the certificate will be a part of the xml
   * @param cert contains the public key for encryption
   * @param supportedEncryptionAlgorithms the supported encryption algorithms. May be empty for defaults.
   * @throws NoSuchAlgorithmException
   * @throws KeyException
   */
  public EidasEncrypter(boolean includeCert,
                        X509Certificate cert,
                        List<EncryptionAlgorithmInfo> supportedEncryptionAlgorithms)
    throws NoSuchAlgorithmException, KeyException
  {
    PublicKey receiverKey = CredentialSupport.getSimpleCredential(cert, null).getPublicKey();
    if (receiverKey instanceof RSAKey key)
    {
      int keyLength = key.getModulus().bitLength();
      if (keyLength < MINIMAL_LENGTH_RSA)
      {
        log.debug("Found invalid key length: {}. Key must be at least {}. Cert: {}",
                  keyLength,
                  MINIMAL_LENGTH_RSA,
                  cert);
        throw new KeyException("Key length is less than %s bit: %s".formatted(MINIMAL_LENGTH_RSA, keyLength));
      }
    }
    else if (receiverKey instanceof ECKey key)
    {
      int keyLength = key.getParams().getCurve().getField().getFieldSize();
      if (keyLength < MINIMAL_LENGTH_EC)
      {
        log.debug("Found invalid key length: {}. Key must be at least {}. Cert: {}",
                  keyLength,
                  MINIMAL_LENGTH_EC,
                  cert);
        throw new KeyException("Key length is less than %s bit: %s".formatted(MINIMAL_LENGTH_EC, keyLength));
      }
    }

    String contentEncryptionAlgo = supportedEncryptionAlgorithms.stream()
                                                                .map(EncryptionAlgorithmInfo::getAlgorithm)
                                                                .filter(ALLOWED_CONTENT_ENCRYPTION_ALGORITHMS::contains)
                                                                .findFirst()
                                                                .orElse(DEFAULT_ALGO_CONTENTENCRYPTION);
    log.debug("Using content encryption algorithm: {}", contentEncryptionAlgo);

    Credential symmetricCredential = CredentialSupport.getSimpleCredential(AlgorithmSupport.generateSymmetricKey(contentEncryptionAlgo));
    DataEncryptionParameters encParams = new DataEncryptionParameters();
    encParams.setAlgorithm(contentEncryptionAlgo);
    encParams.setEncryptionCredential(symmetricCredential);

    encrypter = new Encrypter(encParams,
                              getKeyEncryptionParameters(cert,
                                                         "EC".equals(cert.getPublicKey().getAlgorithm()) || includeCert,
                                                         supportedEncryptionAlgorithms));
    encrypter.setKeyPlacement(KeyPlacement.INLINE);
  }

  private static KeyEncryptionParameters getKeyEncryptionParameters(X509Certificate encryptionCertificate,
                                                                    boolean includeCert,
                                                                    List<EncryptionAlgorithmInfo> supportedEncryptionAlgorithms)
    throws NoSuchAlgorithmException, KeyException
  {
    KeyEncryptionParameters kekParameters = new KeyEncryptionParameters();
    String algorithm = encryptionCertificate.getPublicKey().getAlgorithm();
    log.trace("Found the following supported encryption algorithms in metadata: {}.",
              supportedEncryptionAlgorithms.stream()
                                           .map(EncryptionAlgorithmInfo::getAlgorithm)
                                           .collect(Collectors.joining(", ")));


    switch (algorithm)
    {
      case "EC" -> prepareForEC(encryptionCertificate, kekParameters, supportedEncryptionAlgorithms);
      case "RSA" -> prepareForRsa(encryptionCertificate, includeCert, kekParameters, supportedEncryptionAlgorithms);
      default -> throw new NoSuchAlgorithmException("Not supported or unknown standard algorithm name: "
                                                    + encryptionCertificate.getPublicKey().getAlgorithm());
    }

    return kekParameters;
  }

  private static void prepareForRsa(X509Certificate encryptionCertificate,
                                    boolean includeCert,
                                    KeyEncryptionParameters kekParameters,
                                    List<EncryptionAlgorithmInfo> supportedEncryptionAlgorithms)
  {
    Optional<EncryptionAlgorithmInfo> algorithmInfo = supportedEncryptionAlgorithms.stream()
                                                                                   .filter(sea -> ALLOWED_KEY_TRANSPORT_ALGORITHMS.contains(sea.getAlgorithm()))
                                                                                   .findFirst();

    if (algorithmInfo.isPresent())
    {
      log.debug("Preparing SAML RSA encryption with algorithm info form metadata: {}", algorithmInfo.get());
    }
    else
    {
      log.debug("Preparing SAML RSA encryption with defaults");
    }

    String keyTransportAlgo = algorithmInfo.map(EncryptionAlgorithmInfo::getAlgorithm)
                                           .orElse(DEFAULT_ALGO_KEYTRANSPORT);
    log.debug("Using key transport algorithm: {}", keyTransportAlgo);
    kekParameters.setAlgorithm(keyTransportAlgo);

    kekParameters.setEncryptionCredential(CredentialSupport.getSimpleCredential(encryptionCertificate, null));


    String keyDigestAlgo = algorithmInfo.map(EncryptionAlgorithmInfo::getDigestAlgorithm)
                                        .orElse(DEFAULT_ALGO_KEYTRANSPORT_DIGEST);
    log.debug("Using key digest algorithm: {}", keyDigestAlgo);
    String keyTransportMgf = algorithmInfo.map(EncryptionAlgorithmInfo::getMgfAlgorithm)
                                          .orElse(DEFAULT_ALGO_KEYTRANSPORT_MGF);
    log.debug("Using key transport MGF algorithm: {}", keyDigestAlgo);

    kekParameters.setRSAOAEPParameters(new RSAOAEPParameters(keyDigestAlgo, keyTransportMgf, null));
    if (includeCert)
    {
      KeyInfoGeneratorFactory kigf = ConfigurationService.get(EncryptionConfiguration.class)
                                                         .getKeyTransportKeyInfoGeneratorManager()
                                                         .getDefaultManager()
                                                         .getFactory(new BasicX509Credential(encryptionCertificate));
      kekParameters.setKeyInfoGenerator(kigf.newInstance());
    }
  }

  private static void prepareForEC(X509Certificate encryptionCertificate,
                                   KeyEncryptionParameters kekParameters,
                                   List<EncryptionAlgorithmInfo> supportedEncryptionAlgorithms)
    throws KeyException
  {
    Optional<EncryptionAlgorithmInfo> algorithmInfo = supportedEncryptionAlgorithms.stream()
                                                                                   .filter(sea -> ALLOWED_KEY_WRAPPING_ALGORITHMS_AND_MIN_KEY_LENGTH.containsKey(sea.getAlgorithm()))
                                                                                   .findFirst();


    String keyWrappingAlgo = algorithmInfo.map(EncryptionAlgorithmInfo::getAlgorithm).orElse(DEFAULT_ALGO_KEYWRAP);
    log.debug("Using key wrapping algorithm: {}", keyWrappingAlgo);
    kekParameters.setAlgorithm(keyWrappingAlgo);
    Credential keyAgreementCredential = getKeyAgreementCredential(CredentialSupport.getSimpleCredential(encryptionCertificate,
                                                                                                        null),
                                                                  supportedEncryptionAlgorithms,
                                                                  keyWrappingAlgo);
    kekParameters.setEncryptionCredential(keyAgreementCredential);
    KeyAgreementKeyInfoGeneratorFactory newKeyInfoGenerator = new KeyAgreementKeyInfoGeneratorFactory();
    kekParameters.setKeyInfoGenerator(newKeyInfoGenerator.newInstance());
  }

  private static Credential getKeyAgreementCredential(Credential credential,
                                                      List<EncryptionAlgorithmInfo> supportedEncryptionAlgorithms,
                                                      String keyWrappingAlgo)
    throws KeyException
  {
    try
    {
      Optional<EncryptionAlgorithmInfo> optionalKeyAgreementAlgoFromMetadata = supportedEncryptionAlgorithms.stream()
                                                                                                            .filter(k -> ALLOWED_KEY_AGREEMENT_ALGORITHMS_AND_MIN_KEY_LENGTH.containsKey(k.getAlgorithm()))
                                                                                                            .findFirst();

      log.debug("Using key agreement algorithm: {}",
                optionalKeyAgreementAlgoFromMetadata.map(EncryptionAlgorithmInfo::getAlgorithm)
                                                    .orElse(DEFAULT_ALGO_KEYAGREEMENT));

      return KeyAgreementSupport.getProcessor(optionalKeyAgreementAlgoFromMetadata.map(EncryptionAlgorithmInfo::getAlgorithm)
                                                                                  .orElse(DEFAULT_ALGO_KEYAGREEMENT))
                                .execute(credential,
                                         keyWrappingAlgo,
                                         new KeyAgreementParameters(getKeyAgreementParameters(optionalKeyAgreementAlgoFromMetadata)));
    }
    catch (KeyAgreementException | KeyException e)
    {
      throw new KeyException("Could not generate key agreement credentials", e);
    }
  }

  private static @NonNull List<KeyAgreementParameter> getKeyAgreementParameters(Optional<EncryptionAlgorithmInfo> optionalKeyAgreementAlgoFromMetadata)
    throws KeyException
  {

    // Try to get key agreement parameters from metadata
    List<KeyAgreementParameter> keyAgreementParameters = new ArrayList<>();


    // Add KDF Parameter from metadata
    optionalKeyAgreementAlgoFromMetadata.filter(k -> k.getKdfParams() != null && k.getKdfParams().digest() != null)
                                        .map(EncryptionAlgorithmInfo::getKdfParams)
                                        .filter(kdfParams -> ALLOWED_HASH_FUNCTIONS.contains(kdfParams.digest()))
                                        .map(kdfParams -> {
                                          ConcatKDF e = new ConcatKDF();
                                          e.setAlgorithmID(AlgorithmSupport.getAlgorithmID(kdfParams.algorithm()));
                                          e.setDigestMethod(kdfParams.digest());
                                          try
                                          {
                                            e.initialize();
                                          }
                                          catch (ComponentInitializationException ex)
                                          {
                                            log.warn("Could not initialise KDF parameter from metadata", ex);
                                            return null;
                                          }
                                          return e;
                                        })
                                        .ifPresent(keyAgreementParameters::add);

    // Add nonce value from metadata
    optionalKeyAgreementAlgoFromMetadata.filter(k -> k.getKaNonceValue() != null)
                                        .map(EncryptionAlgorithmInfo::getKaNonceValue)
                                        .map(nonceValue -> {
                                          KANonce kaNonce = new KANonce();
                                          kaNonce.setValue(nonceValue);
                                          return kaNonce;
                                        })
                                        .ifPresent(keyAgreementParameters::add);
    // Get key agreement parameter from config if necessary
    if (keyAgreementParameters.isEmpty())
    {
      Collection<KeyAgreementParameter> keyAgreementParameterCollection = SecurityConfigurationSupport.getGlobalEncryptionConfiguration()
                                                                                                      .getKeyAgreementConfigurations()
                                                                                                      .get("EC")
                                                                                                      .getParameters();


      if (keyAgreementParameterCollection == null)
      {
        throw new KeyException("Key agreement parameters are null");
      }
      keyAgreementParameters.addAll(keyAgreementParameterCollection);
    }
    return keyAgreementParameters;
  }
}
