/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.sm;

import java.math.BigInteger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.constants.Constants;
import de.governikus.eumw.poseidas.cardbase.crypto.CipherUtil;


/**
 * Special IvParameterSpec for generation of IV by additional encrypting of increased SSC.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class AESEncSSCIvParameterSpec extends IvParameterSpec
{

  /**
   * Constant for default increment used during increasing SSC: 1.
   *
   * @see #increaseSSC()
   */
  private static final BigInteger DEFAULT_INCREMENT = BigInteger.valueOf(1);

  // length of IV
  private final int ivLength;

  /**
   * Send Sequence Counter.
   */
  protected BigInteger ssc = null;

  // base BigInteger for calculation of iv by adding ssc and cutting the byte array representation of result
  private final BigInteger base;

  // overflow limit (start counting at 0, set SSC to 0 if reached)
  private final BigInteger overflow;

  // iv
  private byte[] iv = null;

  // key used for generation of IV
  private final SecretKey keyEnc;

  /**
   * Constructor with initial send sequence counter as byte[]-array (SSC is increased according to
   * initialIncrease value and first IV generated, IV is the ssc encrypted with given key).
   * <p>
   * Notice: implementation must secure ssc initialization value is untouched by increasing.
   * </p>
   *
   * @param ssc initial send sequence counter as byte[]-array, <code>null</code> or empty array not permitted
   * @param keyEnc encryption key for generation of IV by encrypting SSC, <code>null</code> not permitted,
   *          only AES keys permitted
   * @throws IllegalArgumentException if initial send sequence counter is <code>null</code> or empty array,
   *           key is <code>null</code> or not an AES key
   * @see #increaseSSC()
   */
  public AESEncSSCIvParameterSpec(byte[] ssc, SecretKey keyEnc)
  {
    super(Constants.EMPTY_PRIMITIVE_BYTE_ARRAY);
    AssertUtil.notNullOrEmpty(ssc, "SSC");
    AssertUtil.notNull(keyEnc, "encryption key");
    if (!CipherUtil.ALGORITHM_AES.equals(keyEnc.getAlgorithm()))
    {
      throw new IllegalArgumentException("only " + CipherUtil.ALGORITHM_AES
                                         + "key permitted, but key with algorithm " + keyEnc.getAlgorithm()
                                         + " used");
    }
    this.keyEnc = keyEnc;
    // SSC as unsigned integer from byte-array
    this.ssc = new BigInteger(1, ssc);
    // calculate base BigInteger value iv byte-array calculation based on SSC
    this.base = BigInteger.valueOf(2).pow(8 * ssc.length).negate();
    // calculate BigInteger to start counting at 0 again (BigInteger just increases, if not stopped)
    this.overflow = BigInteger.valueOf(2).pow(8 * ssc.length);
    this.createIV();
    this.ivLength = ssc.length;
  }

  private IvParameterSpec updateEncryptedIV(byte[] iv)
  {
    byte[] result = ByteUtil.copy(iv);
    try
    {
      result = CipherUtil.encipherAES(CipherUtil.ALGORITHM_AES + "/ECB/NoPadding", keyEnc, null, result, null);
    }
    catch (IllegalArgumentException e)
    {
      throw new RuntimeException("generation of IV failed by encrypting SSC with key", e);
    }
    catch (IllegalBlockSizeException e)
    {
      throw new RuntimeException("generation of IV failed by encrypting SSC with key", e);
    }
    catch (BadPaddingException e)
    {
      throw new RuntimeException("generation of IV failed by encrypting SSC with key", e);
    }
    return new IvParameterSpec(result);
  }

  /**
   * Gets encrypted IV.
   *
   * @return encrypted IV
   */
  public synchronized IvParameterSpec getEncryptedIV()
  {
    return updateEncryptedIV(this.iv);
  }

  /**
   * Increase SSC and update IV bytes (initialization vector).
   */
  public synchronized void increaseSSC()
  {
    this.ssc = this.ssc.add(DEFAULT_INCREMENT);
    int comparison = this.overflow.compareTo(this.ssc);
    if (comparison < 1)
    {
      this.ssc = this.ssc.subtract(this.overflow);
    }
    createIV();
  }

  /**
   * Creates IV.
   */
  protected void createIV()
  {
    this.iv = this.base.add(this.ssc).toByteArray();
    this.iv = ByteUtil.subbytes(this.iv, 1);
  }

  /**
   * Gets length of IV.
   *
   * @return length of IV
   */
  public final int getLength()
  {
    return this.ivLength;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public synchronized byte[] getIV()
  {
    return ByteUtil.copy(this.iv);
  }
}
