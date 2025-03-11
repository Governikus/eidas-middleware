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
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Collection;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
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
import org.opensaml.xmlsec.agreement.KeyAgreementProcessor;
import org.opensaml.xmlsec.agreement.KeyAgreementSupport;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.KeyAgreementKeyInfoGeneratorFactory;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class EidasEncrypter
{

  private static final String KEYTRANSPORT_ALGO = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11;

  private static final String KEYTRANSPORT_HASH_ALGO = EncryptionConstants.ALGO_ID_DIGEST_SHA256;

  private static final String KEYTRANSPORT_MGF_ALGO = EncryptionConstants.ALGO_ID_MGF1_SHA256;

  /**
   * Defined in eIDAS Cryptographic Requirement (v1.4.1) chapter 3.2.2.1
   */
  private static final int MINIMAL_RSA_KEY_LENGTH = 3072;

  /**
   * Completely configured encryption handler, null if encryption is not set.
   */
  Encrypter encrypter;

  /**
   * Cipher-Algorithm is set to http://www.w3.org/2009/xmlenc11#aes256-gcm
   *
   * @param includeCert
   * @param cert
   * @throws NoSuchAlgorithmException
   * @throws KeyException
   */
  public EidasEncrypter(boolean includeCert, X509Certificate cert) throws NoSuchAlgorithmException, KeyException
  {
    this(includeCert, cert, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
  }

  /**
   * Create a XMLCipher Object.
   *
   * @param includeCert if true the certificate will be a part of the xml
   * @param cert contains the public key for encryption
   * @param cipherAlgo e.g http://www.w3.org/2009/xmlenc11#aes256-gcm
   * @throws NoSuchAlgorithmException
   * @throws KeyException
   */
  private EidasEncrypter(boolean includeCert, X509Certificate cert, String cipherAlgo)
    throws NoSuchAlgorithmException, KeyException
  {
    Credential receiverCredential = CredentialSupport.getSimpleCredential(cert, null);
    Credential symmetricCredential = CredentialSupport.getSimpleCredential(AlgorithmSupport.generateSymmetricKey(cipherAlgo));

    DataEncryptionParameters encParams = new DataEncryptionParameters();
    encParams.setAlgorithm(cipherAlgo);
    encParams.setEncryptionCredential(symmetricCredential);

    if ("EC".equals(cert.getPublicKey().getAlgorithm()))
    {
      encrypter = new Encrypter(encParams, getKeyEncryptionParameters(cert, true));
    }
    else
    {
      // Check key size -
      if (receiverCredential.getPublicKey() instanceof RSAKey key)
      {
        int keyLength = key.getModulus().bitLength();
        if (keyLength < MINIMAL_RSA_KEY_LENGTH)
        {
          log.debug("Found invalid key length: {}. Key must be at least {}. Cert: {}",
                    keyLength,
                    MINIMAL_RSA_KEY_LENGTH,
                    cert);
          throw new KeyException("Key length is less than %s bit: %s".formatted(MINIMAL_RSA_KEY_LENGTH, keyLength));
        }
      }

      /**
       * key encryption parameters used to set up the {@link #encrypter}, null if encryption is not set. Note that the
       * encrypter will ignore these values given to it in the constructor when it encrypts an XMLObject. In that case,
       * you have to give these values again to the encrypt method.
       */
      KeyEncryptionParameters kek = new KeyEncryptionParameters();
      kek.setAlgorithm(KEYTRANSPORT_ALGO);
      kek.setEncryptionCredential(receiverCredential);
      kek.setRSAOAEPParameters(new RSAOAEPParameters(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256,
                                                     KEYTRANSPORT_MGF_ALGO, null));
      encrypter = new Encrypter(encParams, kek);
      if (includeCert)
      {
        KeyInfoGeneratorFactory kigf = ConfigurationService.get(EncryptionConfiguration.class)
                                                           .getKeyTransportKeyInfoGeneratorManager()
                                                           .getDefaultManager()
                                                           .getFactory(new BasicX509Credential(cert));
        kek.setKeyInfoGenerator(kigf.newInstance());
      }
    }
    encrypter.setKeyPlacement(KeyPlacement.INLINE);
  }

  private static KeyEncryptionParameters getKeyEncryptionParameters(X509Certificate encryptionCertificate,
                                                                    boolean includeCert)
    throws NoSuchAlgorithmException, KeyException
  {
    KeyEncryptionParameters kekParameters = new KeyEncryptionParameters();
    String algorithm = encryptionCertificate.getPublicKey().getAlgorithm();
    return switch (algorithm)
    {
      case "EC" ->
      {
        prepareForEC(encryptionCertificate, kekParameters);
        yield kekParameters;
      }
      case "RSA" ->
      {
        prepareForRsa(encryptionCertificate, includeCert, kekParameters);
        yield kekParameters;
      }
      default -> throw new NoSuchAlgorithmException("Not supported or unknown standard algorithm name: "
                                                    + encryptionCertificate.getPublicKey().getAlgorithm());
    };

  }

  private static void prepareForRsa(X509Certificate encryptionCertificate,
                                    boolean includeCert,
                                    KeyEncryptionParameters kekParameters)
  {
    kekParameters.setAlgorithm(KEYTRANSPORT_ALGO);
    kekParameters.setEncryptionCredential(CredentialSupport.getSimpleCredential(encryptionCertificate, null));
    kekParameters.setRSAOAEPParameters(new RSAOAEPParameters(KEYTRANSPORT_HASH_ALGO, KEYTRANSPORT_MGF_ALGO, null));
    if (includeCert)
    {
      KeyInfoGeneratorFactory kigf = ConfigurationService.get(EncryptionConfiguration.class)
                                                         .getKeyTransportKeyInfoGeneratorManager()
                                                         .getDefaultManager()
                                                         .getFactory(new BasicX509Credential(encryptionCertificate));
      kekParameters.setKeyInfoGenerator(kigf.newInstance());
    }
  }

  private static void prepareForEC(X509Certificate encryptionCertificate, KeyEncryptionParameters kekParameters)
    throws KeyException
  {
    kekParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
    Credential keyAgreementCredential = getKeyAgreementCredential(CredentialSupport.getSimpleCredential(encryptionCertificate,
                                                                                                        null));
    kekParameters.setEncryptionCredential(keyAgreementCredential);
    KeyAgreementKeyInfoGeneratorFactory newKeyInfoGenerator = new KeyAgreementKeyInfoGeneratorFactory();
    kekParameters.setKeyInfoGenerator(newKeyInfoGenerator.newInstance());
  }

  private static Credential getKeyAgreementCredential(Credential credential) throws KeyException
  {
    try
    {
      Collection<KeyAgreementParameter> keyAgreementParameterCollection = SecurityConfigurationSupport.getGlobalEncryptionConfiguration()
                                                                                                      .getKeyAgreementConfigurations()
                                                                                                      .get("EC")
                                                                                                      .getParameters();
      if (keyAgreementParameterCollection == null)
      {
        throw new KeyException("Key agreement parameters are null");
      }

      KeyAgreementParameters keyAgreementParameters = new KeyAgreementParameters(keyAgreementParameterCollection);
      KeyAgreementProcessor keyAgreementProcessor = KeyAgreementSupport.getProcessor("http://www.w3.org/2009/xmlenc11#ECDH-ES");
      return keyAgreementProcessor.execute(credential, EncryptionConstants.ALGO_ID_KEYWRAP_AES256, keyAgreementParameters);

    }
    catch (KeyAgreementException | KeyException var4)
    {
      throw new KeyException("Could not generate key agreement credentials", var4);
    }
  }
}
