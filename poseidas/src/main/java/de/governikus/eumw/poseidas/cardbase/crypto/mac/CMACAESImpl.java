/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;


/**
 * Implementation of CMAC algorithm as per NIST Special Publication 800-38B (with AES block cipher).
 * <p>
 * Note: to be replaced once Java provides own implementation.
 * </p>
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
class CMACAESImpl implements CMAC
{

  /**
   * Constant used in subkey generation.
   */
  private static final byte[] RB = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0x87};

  /**
   * Cipher instance (AES).
   */
  private final Cipher cipher;

  /**
   * Subkey no. 1.
   */
  private byte[] k1 = null;

  /**
   * Subkey no. 2.
   */
  private byte[] k2 = null;

  /**
   * Constant of algorithm: <ocde>AES/ECB/NOPADDING</code>.
   */
  public static final String ALGORITHM = "AES/ECB/NOPADDING";

  /**
   * Constructor.
   * 
   * @param key AES key, <code>null</code> not permitted
   * @param algorithm encryption algorithm, <code>null</code> or empty not permitted, only {@link #ALGORITHM}
   *          permitted
   * @throws IllegalArgumentException if key <code>null</code>, algorithm <code>null</code> or empty or
   *           unsupported
   * @throws InvalidKeyException if key not valid
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   */
  CMACAESImpl(SecretKey key, String algorithm)
    throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException
  {
    super();
    AssertUtil.notNull(key, "key");
    AssertUtil.notNullOrEmpty(algorithm, "algorithm");
    if (!ALGORITHM.equals(algorithm))
    {
      throw new IllegalArgumentException("not supported algorithm: " + algorithm
                                         + ", only permitted algorithm: " + ALGORITHM);
    }
    this.cipher = Cipher.getInstance(ALGORITHM);
    this.cipher.init(Cipher.ENCRYPT_MODE, key);
  }

  /**
   * Generates subkeys.
   * 
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  private void generateSubkeys() throws IllegalBlockSizeException, BadPaddingException
  {
    int bs = this.cipher.getBlockSize();
    byte[] ciphered = this.cipher.doFinal(new byte[bs]);

    if (ByteUtil.isBitSet(ciphered[0], 7))
    {
      this.k1 = ByteUtil.xorBits(ByteUtil.shiftLeft(ciphered), RB);
    }
    else
    {
      this.k1 = ByteUtil.shiftLeft(ciphered);
    }

    if (ByteUtil.isBitSet(this.k1[0], 7))
    {
      this.k2 = ByteUtil.xorBits(ByteUtil.shiftLeft(this.k1), RB);
    }
    else
    {
      this.k2 = ByteUtil.shiftLeft(this.k1);
    }
  }

  /** {@inheritDoc} */
  @Override
  public byte[] mac(byte[] message, int byteLength) throws IllegalBlockSizeException, BadPaddingException
  {
    AssertUtil.notNull(message, "message");
    int bs = this.cipher.getBlockSize();
    if (byteLength > bs)
    {
      throw new IllegalArgumentException("requested length of MAC not possible with present AES cipher");
    }
    if (byteLength < 1)
    {
      throw new IllegalArgumentException("zero or negative length of MAC not possible");
    }

    if (this.k1 == null || this.k2 == null)
    {
      this.generateSubkeys();
    }

    int n;
    if (message.length == 0)
    {
      n = 1;
    }
    else
    {
      n = (message.length / bs) + (message.length % bs > 0 ? 1 : 0);
    }

    byte[] c = new byte[bs];
    Arrays.fill(c, (byte)0x00);
    for ( int i = 1 ; i < n ; i++ )
    {
      byte[] msgPart = ByteUtil.subbytes(message, (i - 1) * bs, i * bs);
      byte[] xorResult = ByteUtil.xorBits(c, msgPart);
      c = this.cipher.doFinal(xorResult);
    }

    byte[] msgPart = ByteUtil.subbytes(message, (n - 1) * bs);
    byte[] innerXorResult;
    if (msgPart.length < bs)
    {
      msgPart = ByteUtil.combine(msgPart, new byte[]{(byte)0x80});
      msgPart = ByteUtil.combine(msgPart, new byte[bs - msgPart.length]);
      innerXorResult = ByteUtil.xorBits(this.k2, msgPart);
    }
    else
    {
      innerXorResult = ByteUtil.xorBits(this.k1, msgPart);
    }
    byte[] xorResult = ByteUtil.xorBits(c, innerXorResult);
    c = this.cipher.doFinal(xorResult);

    return ByteUtil.subbytes(c, 0, byteLength);
  }
}
