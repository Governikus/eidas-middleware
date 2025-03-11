/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardserver.SignatureUtil;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation of {@link HSMService} for using no HSM.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Slf4j
public class BOSHSMSimulatorService implements HSMService
{

  /**
   * Reference to the {@link LocalCertAndKeyProvider}.
   */
  private final LocalCertAndKeyProvider lcakp = LocalCertAndKeyProvider.getInstance();

  /**
   * Single instance.
   */
  private static final BOSHSMSimulatorService SINGLETON = new BOSHSMSimulatorService();

  /**
   * Standard constructor.
   */
  private BOSHSMSimulatorService()
  {
    super();
  }

  /**
   * Gets single instance.
   *
   * @return single instance
   */
  static BOSHSMSimulatorService getInstance()
  {
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
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
  {
    AssertUtil.notNullOrEmpty(algorithm, "algorithm");
    AssertUtil.notNull(spec, "algorithm parameters");
    AssertUtil.notNullOrEmpty(alias, "alias");

    if (!replace && this.lcakp.getKeyByHolder(alias) != null)
    {
      throw new IllegalArgumentException("key with requested alias (" + alias
                                         + ") already existing, replacing not permitted");
    }

    KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    kpg.initialize(spec);
    KeyPair kp = kpg.generateKeyPair();

    // this is no permanent store!
    this.lcakp.addKey(alias, kp.getPrivate().getEncoded());

    return kp;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] sign(String alias, OID sigAlgOID, byte[] data)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException
  {
    AssertUtil.notNullOrEmpty(alias, "alias of key");
    AssertUtil.notNull(sigAlgOID, "OID for signature algorithm");
    AssertUtil.notNullOrEmpty(data, "data to be signed");

    byte[] keyBytes = this.lcakp.getKeyByHolder(alias);
    PrivateKey privSignKey = buildPrivateKey(keyBytes);

    Signature signature = SignatureUtil.createSignature(sigAlgOID);
    signature.initSign(privSignKey);
    signature.update(data);
    return signature.sign();
  }

  public static PrivateKey buildPrivateKey(byte[] keyBytes)
    throws NoSuchAlgorithmException, InvalidKeySpecException
  {
    AssertUtil.notNullOrEmpty(keyBytes, "bytes of received key");

    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
    PrivateKey privSignKey = null;
    try
    {
      privSignKey = KeyFactory.getInstance("EC", SecurityProvider.BOUNCY_CASTLE_PROVIDER)
                              .generatePrivate(keySpec);
    }
    catch (InvalidKeySpecException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to generate EC private key", e);
      }
      privSignKey = KeyFactory.getInstance("RSA", SecurityProvider.BOUNCY_CASTLE_PROVIDER)
                              .generatePrivate(keySpec);
    }
    return privSignKey;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getAliases()
  {
    // there is no permanent key store connected
    return new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override
  public void deleteKey(String alias)
  {
    this.lcakp.removeKey(alias);
  }

  /** {@inheritDoc} */
  @Override
  public boolean containsKey(String alias)
  {
    return this.lcakp.getKeyByHolder(alias) != null;
  }

  /** {@inheritDoc} */
  @Override
  public void init(HSMConfiguration config)
  {
    throw new UnsupportedOperationException("init not required");
  }

  /** {@inheritDoc} */
  @Override
  public boolean isAlive(boolean allInstances)
  {
    // always true as there is no login that can fail, no connection that can break down
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public void logout()
  {
    throw new UnsupportedOperationException("logout not required");
  }

  /** {@inheritDoc} */
  @Override
  public Date getGenerationDate(String alias)
  {
    throw new UnsupportedOperationException("there is no permanent key store connected");
  }

  /** {@inheritDoc} */
  @Override
  public Date getExpirationDate(String alias)
  {
    throw new UnsupportedOperationException("there is no permanent key store connected");
  }

  /** {@inheritDoc} */
  @Override
  public boolean isKeyBeingModified(String alias)
  {
    return false;
  }

  /** {@inheritDoc} */
  @Override
  public PublicKey getPublicKey(String alias)
  {
    throw new UnsupportedOperationException("public key is not stored");
  }

  /** {@inheritDoc} */
  @Override
  public void distributeKey(String alias)
  {
    // nothing
  }

  /** {@inheritDoc} */
  @Override
  public boolean isInitialized()
  {
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] exportKey(String alias)
  {
    return lcakp.getKeyByHolder(alias);
  }

  /** {@inheritDoc} */
  @Override
  public KeyStore getKeyStore()
  {
    return null;
  }
}
