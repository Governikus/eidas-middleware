/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.kdf;

import java.security.MessageDigest;

import javax.crypto.SecretKey;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;


/**
 * Abstract KeyDerivationFunction (KDF) as specified in TR-03110 Part3 v2.10, section A.2.3 used for 3DES and
 * AES.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public abstract class AbstractKeyDerivationFunction
{

  /**
   * Constant indicating derivation of encryption key.
   */
  static final byte[] KDF_ENC = new byte[]{0x00, 0x00, 0x00, 0x01};

  /**
   * Constant indicating derivation of MAC key.
   */
  static final byte[] KDF_MAC = new byte[]{0x00, 0x00, 0x00, 0x02};

  /**
   * Constant indicating derivation of nonce decryption key.
   */
  static final byte[] KDF_PI = new byte[]{0x00, 0x00, 0x00, 0x03};

  /**
   * Digest instance.
   */
  private final MessageDigest digest;

  /**
   * Constructor.
   *
   * @param digest digest, <code>null</code> not permitted
   * @throws IllegalArgumentException if digest <code>null</code>
   */
  AbstractKeyDerivationFunction(MessageDigest digest)
  {
    super();
    AssertUtil.notNull(digest, "MessageDigest");
    this.digest = digest;
  }

  /**
   * The general key derivation function.
   *
   * @param k shared secret value (required), <code>null</code> or empty array not permitted
   * @param r nonce (optional), <code>null</code> permitted
   * @param c 4 byte/32 bit big endian integer (required), <code>null</code> not permitted
   * @return derived keydata
   * @throws IllegalArgumentException if required parameter <code>null</code> or empty
   */
  byte[] h(byte[] k, byte[] r, byte[] c)
  {
    AssertUtil.notNullOrEmpty(k, "k");
    if (c == null || c.length != 4)
    {
      throw new IllegalArgumentException("c must be 4 bytes");
    }

    byte[] kInt = k;
    if (r != null)
    {
      kInt = ByteUtil.combine(kInt, r);
    }
    kInt = ByteUtil.combine(kInt, c);
    return this.digest.digest(kInt);
  }

  /**
   * The general key derivation function.
   *
   * @param k shared secret, <code>null</code> or empty array not permitted
   * @param r nonce, <code>null</code> permitted
   * @param c 4 byte big endian integer, <code>null</code> not permitted
   * @return derived secret key
   * @throws IllegalArgumentException if required parameter <code>null</code> or empty
   */
  abstract SecretKey kdf(byte[] k, byte[] r, byte[] c);
}
