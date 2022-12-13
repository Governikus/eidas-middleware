/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.RSAOAEPParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;

import se.swedenconnect.opensaml.xmlsec.config.ExtendedDefaultSecurityConfigurationBootstrap;
import se.swedenconnect.opensaml.xmlsec.encryption.support.ECDHKeyAgreementParameters;


public class EidasEncrypter
{

  /**
   * Completely configured encryption handler, null if encryption is not set.
   */
  Encrypter encrypter;

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
      ECDHKeyAgreementParameters ecdhKeyAgreementParameters = new ECDHKeyAgreementParameters();
      ecdhKeyAgreementParameters.setPeerCredential(receiverCredential);
      ecdhKeyAgreementParameters.setKeyInfoGenerator(ExtendedDefaultSecurityConfigurationBootstrap.buildDefaultKeyAgreementKeyInfoGeneratorFactory()
                                                                                                  .newInstance());
      encrypter = new Encrypter(encParams, ecdhKeyAgreementParameters);
    }

    else
    {

      /**
       * key encryption parameters used to set up the {@link #encrypter}, null if encryption is not set. Note
       * that the encrypter will ignore these values given to it in the constructor when it encrypts an
       * XMLObject. In that case, you have to give these values again to the encrypt method.
       */
      KeyEncryptionParameters kek = new KeyEncryptionParameters();
      kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
      kek.setEncryptionCredential(receiverCredential);
      kek.setRSAOAEPParameters(new RSAOAEPParameters(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, null,
                                                     null));
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

  /**
   * Cipher-Algorithm is set to http://www.w3.org/2009/xmlenc11#aes256-gcm
   *
   * @param includeCert
   * @param cert
   * @throws NoSuchAlgorithmException
   * @throws KeyException
   */
  public EidasEncrypter(boolean includeCert, X509Certificate cert)
    throws NoSuchAlgorithmException, KeyException
  {
    this(includeCert, cert, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
  }
}
