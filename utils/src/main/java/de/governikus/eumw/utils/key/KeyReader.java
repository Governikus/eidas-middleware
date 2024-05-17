/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.utils.key;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import de.governikus.eumw.utils.key.exceptions.CertificateCreationException;
import de.governikus.eumw.utils.key.exceptions.KeyGenerationException;
import lombok.extern.slf4j.Slf4j;


/**
 * will provide support methods to translate keys to java objects
 */
@Slf4j
public final class KeyReader
{

  /**
   * utility class constructor
   */
  private KeyReader()
  {
    super();
  }

  /**
   * will read a private rsa or ec key from a given byte-array of a {@link PKCS8EncodedKeySpec}
   *
   * @param privateKey the bytes of the rsa or ec key
   * @return the private-key interface implementation of rsa or ec
   * @throws KeyGenerationException if the private key could not be created from the given byte-array
   */
  public static PrivateKey readPrivateKey(byte[] privateKey)
  {
    if (log.isTraceEnabled())
    {
      log.trace("trying to create private key. privateKey.length: {}-bytes", privateKey.length);
    }
    KeyFactory keyFactory;
    try
    {
      keyFactory = KeyFactory.getInstance("RSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new KeyGenerationException("could not create private key since the RSA algorithm was not found.",
                                       e);
    }
    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey);
    try
    {
      return keyFactory.generatePrivate(privateKeySpec);
    }
    catch (InvalidKeySpecException e)
    {
      log.trace("could not read a private rsa key from the given byte-array", e);
    }

    try
    {
      keyFactory = KeyFactory.getInstance("EC", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new KeyGenerationException("could not create private key since the EC algorithm was not found.",
                                       e);
    }
    privateKeySpec = new PKCS8EncodedKeySpec(privateKey);
    try
    {
      return keyFactory.generatePrivate(privateKeySpec);
    }
    catch (InvalidKeySpecException e)
    {
      log.trace("could not read a private ec key from the given byte-array", e);
    }
    throw new KeyGenerationException("could not read a private rsa or ec key from the given byte-array");
  }

  /**
   * will read a public rsa key from a given byte-array of a {@link X509EncodedKeySpec}
   *
   * @param publicKey the bytes of the rsa key
   * @return the public-key interface implementation of rsa
   * @throws KeyGenerationException if the public key could not be created from the given byte-array
   */
  public static PublicKey readPublicRSAKey(byte[] publicKey)
  {
    if (log.isTraceEnabled())
    {
      log.trace("trying to create public key. publicKey.length: {}-bytes", publicKey.length);
    }
    KeyFactory keyFactory = null;
    try
    {
      keyFactory = KeyFactory.getInstance("RSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new KeyGenerationException("could not create public key since the RSA algorithm was not found.",
                                       e);
    }
    try
    {
      return keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
    }
    catch (InvalidKeySpecException e)
    {
      throw new KeyGenerationException("could not read a public rsa key from the given byte-array", e);
    }
  }

  /**
   * should read a X509 certificate from the given byte-array
   *
   * @param certificateBytes the bytes of the certificate
   * @return the X509 certificate
   * @throws CertificateCreationException if the certificate could not be created from the given data.
   */
  public static X509Certificate readX509Certificate(byte[] certificateBytes)
  {
    if (log.isTraceEnabled())
    {
      log.trace("read X509 certificate. certificate.length: {}-bytes", certificateBytes.length);
    }

    return readX509Certificate(new ByteArrayInputStream(certificateBytes));
  }

  /**
   * should read a X509 certificate from the given byte-array
   *
   * @param certificateStream the certificate inputstream
   * @return the X509 certificate
   * @throws CertificateCreationException if the certificate could not be created from the given data.
   */
  public static X509Certificate readX509Certificate(InputStream certificateStream)
  {
    try (InputStream in = certificateStream)
    {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509",
                                                                      SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      X509Certificate x509Certificate = (X509Certificate)certFactory.generateCertificate(in);
      if (x509Certificate == null)
      {
        throw new CertificateCreationException("the byte-array does not seem to contain data of a X509"
                                               + " certificate.");
      }
      if (log.isTraceEnabled())
      {
        log.trace("X509 certificate was successfully read.");
      }
      return x509Certificate;
    }
    catch (CertificateException | IOException e)
    {
      throw new CertificateCreationException("was not able to create X509 certificate from byte-array", e);
    }
  }
}
