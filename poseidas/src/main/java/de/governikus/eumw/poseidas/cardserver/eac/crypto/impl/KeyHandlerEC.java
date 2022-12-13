/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.crypto.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.math.ec.ECPoint;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.key.KeyHandler;
import de.governikus.eumw.utils.key.SecurityProvider;


/**
 * Implementation of {@link KeyHandler} for EC keys (Bouncy Castle version).
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class KeyHandlerEC extends de.governikus.eumw.poseidas.cardbase.crypto.key.KeyHandlerEC
  implements KeyHandler
{

  /**
   * Reference to a {@link KeyPairGenerator}.
   */
  private KeyPairGenerator kpg = null;

  /**
   * Default constructor.
   *
   * @param fieldSize size of EC field in bytes, must be at least 1.
   * @throws IllegalArgumentException if field size not at least 1
   */
  public KeyHandlerEC(int fieldSize)
  {
    super(fieldSize);
  }

  /** {@inheritDoc} */
  @Override
  public KeyPair generateKeyPair(AlgorithmParameterSpec spec)
    throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
  {
    AssertUtil.notNull(spec, "spec");
    if (this.kpg == null)
    {
      this.kpg = KeyPairGenerator.getInstance("EC", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    this.kpg.initialize(spec);
    return this.kpg.genKeyPair();
  }

  /** {@inheritDoc} */
  @Override
  public byte[] calculateSharedSecret(PrivateKey priv, PublicKey pub)
  {
    AssertUtil.notNull(priv, "private key");
    AssertUtil.notNull(pub, "public key");
    if (!(priv instanceof JCEECPrivateKey) || !(pub instanceof JCEECPublicKey))
    {
      if (!(priv instanceof ECPrivateKey) || !(pub instanceof ECPublicKey))
      {
        throw new IllegalArgumentException("unsupported key type");
      }
      return super.calculateSharedSecret(priv, pub);
    }
    ECPoint sharedPoint = ((JCEECPublicKey)pub).getQ().multiply(((JCEECPrivateKey)priv).getD());
    return ByteUtil.trimByteArray(sharedPoint.normalize().getXCoord().toBigInteger().toByteArray(),
                                  super.fieldSize);
  }
}
