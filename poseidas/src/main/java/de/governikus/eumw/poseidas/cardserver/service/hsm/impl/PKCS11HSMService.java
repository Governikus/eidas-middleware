/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.operator.OperatorCreationException;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateServiceImpl;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation of {@link HSMService} for the PKCS#11 based HSM.
 *
 * @author ast
 */
@Slf4j
public final class PKCS11HSMService implements HSMService
{

  private static final String MESSAGE_NOT_INITIALIZED = "HSM service not initialized";

  /**
   * PKCS#11 security provider.
   */
  private Provider provider;

  /**
   * Keystore from PKCS#11 provider.
   */
  @Getter
  private KeyStore keyStore;

  /**
   * Configuration data.
   */
  private PKCS11HSMConfiguration config;

  /**
   * Single instance.
   */
  private static PKCS11HSMService SINGLETON;

  /**
   * Default Constructor.
   */
  private PKCS11HSMService()
  {
    super();
  }

  /**
   * Gets single instance.
   *
   * @return single instance
   */
  public static synchronized PKCS11HSMService getInstance()
  {
    if (SINGLETON == null)
    {
      SINGLETON = new PKCS11HSMService();
    }
    return SINGLETON;
  }

  /** {@inheritDoc} */
  @Override
  public KeyPair generateKeyPair(String algorithm,
                                 AlgorithmParameterSpec spec,
                                 String alias,
                                 String issuerAlias,
                                 boolean replace,
                                 int lifespan)
    throws NoSuchAlgorithmException, IllegalArgumentException, HSMException, InvalidAlgorithmParameterException,
    IllegalStateException, CertificateException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }

    if (containsKey(alias))
    {
      if (replace)
      {
        deleteKey(alias);
      }
      else
      {
        throw new IllegalArgumentException("key with requested alias (" + alias
                                           + ") already existing, replacing not permitted");
      }
    }

    KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
    kpg.initialize(spec);
    KeyPair kp = kpg.generateKeyPair();

    PrivateKey signer = kp.getPrivate();
    String issuerCN = "CN=" + alias;

    if (StringUtil.notNullOrEmpty(issuerAlias))
    {
      try
      {
        signer = (PrivateKey)keyStore.getKey(issuerAlias, null);
        issuerCN = "CN=" + issuerAlias;
      }
      catch (UnrecoverableKeyException | KeyStoreException e)
      {
        if (log.isDebugEnabled())
        {
          log.debug("Failed to get key from keystore", e);
        }
        // nothing, use self sign
      }
    }

    try
    {
      Certificate cert = CertificateUtil.createSignedCert(kp.getPublic(),
                                                          signer,
                                                          "CN=" + alias + (isRscAlias(alias)
                                                            ? RequestSignerCertificateServiceImpl.OU_REQUEST_SIGNER_CERTIFICATE
                                                            : ""),
                                                          issuerCN + (isRscAlias(issuerCN)
                                                            ? RequestSignerCertificateServiceImpl.OU_REQUEST_SIGNER_CERTIFICATE
                                                            : ""),
                                                          lifespan,
                                                          provider);
      keyStore.setKeyEntry(alias, kp.getPrivate(), null, new Certificate[]{cert});
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
    catch (CertificateException | OperatorCreationException e)
    {
      throw new CertificateException("Failed to create certificate.", e);
    }
    return kp;
  }

  static boolean isRscAlias(String alias)
  {
    if (alias == null || alias.length() < 5)
    {
      return false;
    }
    return "RSC".equals(alias.substring(alias.length() - 5, alias.length() - 2));
  }

  /** {@inheritDoc} */
  @Override
  public byte[] sign(String alias, OID sigAlgOID, byte[] data)
    throws IllegalArgumentException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException,
    KeyStoreException, InvalidKeyException, SignatureException, IllegalStateException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    Signature s = Signature.getInstance(algNameFromOID(sigAlgOID), provider);
    s.initSign((PrivateKey)keyStore.getKey(alias, null));

    s.update(data);
    byte[] sig = s.sign();
    if (rawRequired(sigAlgOID))
    {
      ECPublicKey pk = (ECPublicKey)keyStore.getCertificate(alias).getPublicKey();
      return convertToRaw(sig, pk.getParams().getCurve().getField().getFieldSize() / 8);
    }
    else
    {
      return sig;
    }
  }

  private static boolean rawRequired(OID oid)
  {
    if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_1) || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_224)
        || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_256) || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_384)
        || oid.equals(OIDConstants.OID_TA_ECDSA_SHA_512))
    {
      return true;
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_1) || oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_256)
             || oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_512) || oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_1)
             || oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_256) || oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_512))
    {
      return false;
    }
    throw new IllegalArgumentException("unknown OID");
  }

  private static byte[] convertToRaw(byte[] sig, int trimLen) throws IOException
  {
    ASN1 asn1 = new ASN1(sig);
    ASN1[] children = asn1.getChildElements();
    if (children.length != 2)
    {
      throw new IllegalArgumentException("input is not a signature");
    }
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(ByteUtil.trimByteArray(children[0].getValue(), trimLen));
    baos.write(ByteUtil.trimByteArray(children[1].getValue(), trimLen));
    return baos.toByteArray();
  }

  private static String algNameFromOID(OID oid)
  {
    if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_1))
    {
      return "SHA1withECDSA";
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_224))
    {
      return "SHA224withECDSA";
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_256))
    {
      return "SHA256withECDSA";
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_384))
    {
      return "SHA384withECDSA";
    }
    else if (oid.equals(OIDConstants.OID_TA_ECDSA_SHA_512))
    {
      return "SHA512withECDSA";
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_1))
    {
      return "SHA1withRSASSA-PSS";
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_256))
    {
      return "SHA256withRSASSA-PSS";
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_PSS_SHA_512))
    {
      return "SHA512withRSASSA-PSS";
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_1))
    {
      return "SHA1withRSA";
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_256))
    {
      return "SHA256withRSA";
    }
    else if (oid.equals(OIDConstants.OID_TA_RSA_V1_5_SHA_512))
    {
      return "SHA512withRSA";
    }
    throw new IllegalArgumentException("unknown OID");
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getAliases() throws HSMException, IllegalStateException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    Enumeration<String> aliases;
    try
    {
      aliases = keyStore.aliases();
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
    List<String> result = new ArrayList<>();
    while (aliases.hasMoreElements())
    {
      result.add(aliases.nextElement());
    }
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public void deleteKey(String alias) throws HSMException, IllegalStateException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    try
    {
      keyStore.deleteEntry(alias);
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean containsKey(String alias) throws IllegalArgumentException, HSMException, IllegalStateException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    try
    {
      return keyStore.containsAlias(alias);
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void init(HSMConfiguration config) throws IllegalArgumentException, HSMException
  {
    AssertUtil.notNull(config, "configuration");
    if (!(config instanceof PKCS11HSMConfiguration))
    {
      throw new IllegalArgumentException("PKCS11HSMService requires PKCS11HSMConfiguration for init");
    }
    this.config = (PKCS11HSMConfiguration)config;

    Provider p = Security.getProvider("SunPKCS11");
    provider = p.configure(this.config.getConfigFileName());
    Security.addProvider(provider);
    try
    {
      keyStore = KeyStore.getInstance("PKCS11", provider);
      keyStore.load(null, this.config.getPassword().toCharArray());
    }
    catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e)
    {
      keyStore = null;
      Security.removeProvider(provider.getName());
      provider = null;
      this.config = null;
      throw new HSMException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void logout() throws IllegalStateException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    keyStore = null;
    config = null;
    Security.removeProvider(provider.getName());
    provider = null;
  }

  /** {@inheritDoc} */
  @Override
  public Date getGenerationDate(String alias) throws IllegalArgumentException, IllegalStateException, HSMException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    try
    {
      X509Certificate x509 = (X509Certificate)keyStore.getCertificate(alias);
      if (x509 == null)
      {
        return null;
      }
      return x509.getNotBefore();
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey(String alias) throws HSMException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    try
    {
      Certificate c = keyStore.getCertificate(alias);
      if (c == null)
      {
        return null;
      }
      return c.getPublicKey();
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isAlive(boolean allInstances) throws HSMException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    try
    {
      return keyStore.aliases() != null;
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isInitialized()
  {
    return keyStore != null;
  }

  /** {@inheritDoc} */
  @Override
  public Date getExpirationDate(String alias) throws HSMException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    try
    {
      X509Certificate x509 = (X509Certificate)keyStore.getCertificate(alias);
      if (x509 == null)
      {
        return null;
      }
      return x509.getNotAfter();
    }
    catch (KeyStoreException e)
    {
      throw new HSMException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isKeyBeingModified(String alias)
  {
    return false;
  }

  /** {@inheritDoc} */
  @Override
  public void distributeKey(String alias)
  {
    // nothing to do
  }

  /** {@inheritDoc} */
  @Override
  public byte[] exportKey(String alias) throws HSMException
  {
    if (keyStore == null)
    {
      throw new IllegalStateException(MESSAGE_NOT_INITIALIZED);
    }
    try
    {
      return keyStore.getKey(alias, null).getEncoded();
    }
    catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e)
    {
      throw new HSMException(e);
    }
  }
}
