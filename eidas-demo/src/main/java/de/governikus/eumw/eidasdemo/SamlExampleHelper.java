/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasdemo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import jakarta.annotation.PostConstruct;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.eidas.ext.SPTypeEnumeration;


/**
 * A helper and configuration store for the eIDAS Demo Application. This stores the certificates and URLs needed to
 * communicate with the eIDAS Middleware and also provides some generic functions used in this example
 *
 * @author prange
 */
@Slf4j
@Component
public class SamlExampleHelper
{

  /**
   * URL where the eIDAS Middleware is deployed
   */
  @Value("${middleware.samlreceiverurl}")
  String serverSamlReceiverUrl;

  /**
   * Signature certificate of eIDAS Middleware. It used to verify the eIDAS response from the eIDAS Middleware.<br>
   * Obtain the certificate from the eIDAS Middleware administrator or extract it from the metadata located at
   * http://[eIDAS-MW]/eidas-middleware/Metadata
   */
  X509Certificate serverSigCert;

  /**
   * Path to eIDAS Middleware signature certificate
   */
  @Value("${middleware.signature.certificate}")
  private String serverSigCertPath;

  /**
   * Your own signature certificate belonging to the {@link #demoSignatureKey}.<br>
   * The eIDAS SAML Requests are signed with the key belonging to this certificate. <br>
   * Give this certificate to the eIDAS Middleware Server administrator so the server can verify your requests. This
   * should be a signature certificate, but does not have to be issued by any special certificate authority, it could
   * be, a self signed certificate also fits the needs.<br>
   * You could just generate this certificate and a key with openssl or java keytool on your locale machine.
   */
  X509Certificate demoSignatureCertificate;

  /**
   * Private key matching your signature certificate <br>
   * You should not give this key to anyone including the eIDAS Middleware Server administrator.
   */
  PrivateKey demoSignatureKey;

  /**
   * Path to the signature keystore
   */
  @Value("${demo.signature.keystore}")
  private String demoSignatureKeystorePath;

  /**
   * Alias for the entry in the keystore
   */
  @Value("${demo.signature.alias}")
  private String demoSignatureKeystoreAlias;

  /**
   * Pin for the keystore and the key itself
   */
  @Value("${demo.signature.pin}")
  private String demoSignatureKeystorePin;

  /**
   * Keypair to decrypt the incoming eIDAS responses that are signed by the eIDAS Middleware with the public certificate
   * of this key pair. <br>
   * You should not give the private key to anyone including the eIDAS Middleware Server administrator.
   */
  X509KeyPair demoDecryptionKeyPair;

  /**
   * Path to the decryption keystore
   */
  @Value("${demo.decryption.keystore}")
  private String demoDecryptionKeystorePath;

  /**
   * Alias for the entry in the keystore
   */
  @Value("${demo.decryption.alias}")
  private String demoDecryptionKeystoreAlias;

  /**
   * Pin for the keystore and the key itself
   */
  @Value("${demo.decryption.pin}")
  private String demoDecryptionKeystorePin;

  @Value("${demo.metadata.sptype:public}")
  private String demoMetadataSPType;

  /**
   * This method is called on application startup to load the keystores and URLs.
   */
  @PostConstruct
  private void loadCertificates()
  {
    try
    {
      serverSigCert = Utils.readCert(new FileInputStream(serverSigCertPath));
    }
    catch (FileNotFoundException | CertificateException e)
    {
      log.error("Cannot load server signature certificate", e);
    }

    try (FileInputStream signatureKeystore = new FileInputStream(demoSignatureKeystorePath))
    {
      X509KeyPair keyPair = Utils.readKeyAndCert(signatureKeystore,
                                                 getKeystoreType(demoSignatureKeystorePath),
                                                 demoSignatureKeystorePin.toCharArray(),
                                                 demoSignatureKeystoreAlias,
                                                 demoSignatureKeystorePin.toCharArray(),
                                                 true);
      demoSignatureCertificate = keyPair.getCert();
      demoSignatureKey = keyPair.getKey();
    }
    catch (Exception e)
    {
      log.error("Cannot load signature keystore", e);
    }

    try (FileInputStream decryptionKeystore = new FileInputStream(demoDecryptionKeystorePath))
    {
      demoDecryptionKeyPair = Utils.readKeyAndCert(decryptionKeystore,
                                                   getKeystoreType(demoDecryptionKeystorePath),
                                                   demoDecryptionKeystorePin.toCharArray(),
                                                   demoDecryptionKeystoreAlias,
                                                   demoDecryptionKeystorePin.toCharArray(),
                                                   true);
    }
    catch (Exception e)
    {
      log.error("Cannot load signature keystore", e);
    }
  }

  SPTypeEnumeration getMetadataSPType()
  {
    if (SPTypeEnumeration.PUBLIC.getValue().equalsIgnoreCase(demoMetadataSPType))
    {
      return SPTypeEnumeration.PUBLIC;
    }
    else if (SPTypeEnumeration.PRIVATE.getValue().equalsIgnoreCase(demoMetadataSPType))
    {
      return SPTypeEnumeration.PRIVATE;
    }
    else if ("none".equalsIgnoreCase(demoMetadataSPType))
    {
      return null;
    }
    else
    {
      throw new IllegalArgumentException("Unknown value for 'demo.metadata.sptype': " + demoMetadataSPType);
    }
  }

  /**
   * Return the keystore type. The keystore must be of the type JKS or PKCS12, otherwise an IOException is thrown.
   *
   * @param path Path on the filesystem
   * @return the Keystore type
   * @throws IOException Thrown if the path does not end with jks, p12 or pfx.
   */
  private String getKeystoreType(String path) throws IOException
  {
    if (StringUtils.endsWithIgnoreCase(path, "jks"))
    {
      return "JKS";
    }
    else if (StringUtils.endsWithIgnoreCase(path, "p12") || StringUtils.endsWithIgnoreCase(path, "pfx"))
    {
      return "PKCS12";
    }
    throw new IOException("Keystore must end with .jks, .p12 or .pfx");
  }


}
