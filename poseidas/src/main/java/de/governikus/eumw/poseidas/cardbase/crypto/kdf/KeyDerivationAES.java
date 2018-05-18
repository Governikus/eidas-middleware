/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.kdf;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;


/**
 * AES implementation of {@link KeyDerivationHandler} as specified in TR-03110 Part3 v2.10, section A.2.3.2
 * for AES.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
class KeyDerivationAES extends AbstractKeyDerivationFunction implements KeyDerivationHandler
{

  // key algorithm of generated keys
  private static final String SECRET_KEY_ALGORITHM = "AES";

  /**
   * Length of key data used by derivation.
   */
  private final int keyDataLength;

  /**
   * Constructor.
   * 
   * @param keyLength required key length, must be <code>128</code>, <code>192</code> or <code>256</code>
   * @throws IllegalArgumentException if keyLength not one of the accepted values
   * @throws NoSuchAlgorithmException
   */
  KeyDerivationAES(int keyLength) throws NoSuchAlgorithmException
  {
    // keyLength == 128: use SHA1
    // keyLength == 192 || keyLength == 256: use SHA 256
    super(keyLength == 128 ? MessageDigest.getInstance("SHA-1") : MessageDigest.getInstance("SHA-256"));
    if (keyLength != 128 && keyLength != 192 && keyLength != 256)
    {
      throw new IllegalArgumentException("value " + keyLength + " for keyLength not accepted");
    }
    // keyLength == 128: bytes 1..16 used of SHA1 with 20 bytes
    // keyLength == 192: bytes 1..24 used of SHA256 with 32 bytes
    // keyLength == 256: bytes 1..32 used of SHA256 with 32 bytes
    this.keyDataLength = keyLength / 8;
  }

  /** {@inheritDoc} */
  @Override
  public final SecretKey deriveEncKey(byte[] data, byte[] nonce)
  {
    return this.kdf(data, nonce, KDF_ENC);
  }

  /** {@inheritDoc} */
  @Override
  public final SecretKey deriveMACKey(byte[] data, byte[] nonce)
  {
    return this.kdf(data, nonce, KDF_MAC);
  }

  /** {@inheritDoc} */
  @Override
  public final SecretKey deriveCANPINPUKKey(byte[] data)
  {
    AssertUtil.notNullOrEmpty(data, "key derivation data");
    return this.kdf(data, null, KDF_PI);
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
  @Override
  SecretKey kdf(byte[] k, byte[] r, byte[] c)
  {
    byte[] keydata = super.h(k, r, c);
    return new SecretKeySpec(keydata, 0, this.keyDataLength, SECRET_KEY_ALGORITHM);
  }

}
