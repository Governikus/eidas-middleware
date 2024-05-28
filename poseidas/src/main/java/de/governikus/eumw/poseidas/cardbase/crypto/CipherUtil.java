/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;


/**
 * Some convenience methods for encrypting/decrypting purposes.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class CipherUtil
{

  /**
   * Constant of AES algorithm name: <tt>AES</tt>.
   */
  public static final String ALGORITHM_AES = "AES";

  /**
   * Constant of AES initialization vector length (count of bytes): <tt>16</tt>.
   */
  public static final int AES_IV_LENGTH = 16;

  /**
   * Constant of AES CMAC minimum length (count of bytes): <tt>1</tt>.
   *
   * @see #AES_CMAC_MAXIMUM_LENGTH
   */
  private static final int AES_CMAC_MINIMUM_LENGTH = 1;

  /**
   * Constant for the expected length of a MAC.
   */
  public static final int AES_CMAC_DEFAULT_LENGTH = 8;

  /**
   * Constant of AES CMAC maximum length (same as initialization vector length, count of bytes): <tt>16</tt>.
   *
   * @see #AES_IV_LENGTH
   * @see #AES_CMAC_MINIMUM_LENGTH
   */
  private static final int AES_CMAC_MAXIMUM_LENGTH = AES_IV_LENGTH;

  /**
   * List of key sizes permitted for AES: 16 (128bit), 24 (192bit) and 32 (256bit).
   */
  private static final List<Integer> KEY_SIZES_LIST_AES = Collections.unmodifiableList(Arrays.asList(16,
                                                                                                     24,
                                                                                                     32));

  /**
   * Constructor.
   */
  private CipherUtil()
  {
    super();
  }

  /**
   * Gets cipher for SecretKey, mode and initialization vector, maybe usable for DES, 3DES and AES supporting
   * IvParameterSpec only.
   *
   * @param algorithm algorithm, <code>null</code> or empty String not permitted
   * @param key key, <code>null</code> not permitted
   * @param mode mode of Cipher, {@link Cipher#ENCRYPT_MODE}, {@link Cipher#DECRYPT_MODE},
   *          {@link Cipher#WRAP_MODE} or , {@link Cipher#UNWRAP_MODE} only permitted
   * @param iv initialization vector, <code>null</code> not permitted or specification with <code>null</code>
   *          or empty byte array as IV ({@link IvParameterSpec#getIV()}), only possible for ECB block mode
   * @param provider name of provider, <code>null</code> for wildcard
   * @return Cipher-instance
   * @throws IllegalArgumentException if algorithm, key, mode or initialization not permitted, algorithm, key
   *           or parameters not supported
   * @see Cipher#getInstance(String)
   * @see Cipher#init(int, java.security.Key, java.security.spec.AlgorithmParameterSpec)
   */
  private static final Cipher getCipher(String algorithm,
                                        SecretKey key,
                                        int mode,
                                        IvParameterSpec iv,
                                        String provider)
  {
    // first check arguments contain valid values
    checkGetCipherArguments(algorithm, key, mode, iv, provider);
    // create cipher with/without provider
    Cipher c = null;
    try
    {
      if (provider == null)
      {
        c = Cipher.getInstance(algorithm);
      }
      else
      {
        c = Cipher.getInstance(algorithm, provider);
      }
    }
    catch (NoSuchProviderException e)
    {
      // provider checked before, can not reach here
      throw new IllegalArgumentException("no provider available: " + provider, e);
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new IllegalArgumentException("no algorithm available: " + algorithm, e);
    }
    catch (NoSuchPaddingException e)
    {
      // SUN internally throws instead a NoSuchAlgorithmException not according to method signature, where
      // this Exception declared, so code coverage maybe only possible for provider implementing Cipher
      // correctly (for tests use BC to force this exception)
      throw new IllegalArgumentException("illegal padding: " + algorithm, e);
    }
    // initialize cipher instance with mode, key and init vector
    try
    {
      c.init(mode, key, iv);
    }
    catch (InvalidKeyException e)
    {
      throw new IllegalArgumentException("invalid key: " + key + ", message: " + e.getMessage(), e);
    }
    catch (InvalidAlgorithmParameterException e)
    {
      throw new IllegalArgumentException("invalid algorithm parameters: " + iv + ", message: "
                                         + e.getMessage(), e);
    }
    return c;
  }

  /**
   * Checks arguments at {@link #getCipher(String, SecretKey, int, IvParameterSpec, String)}.
   *
   * @param algorithm algorithm, <code>null</code> or empty String not permitted
   * @param key key, <code>null</code> not permitted
   * @param mode mode of Cipher, {@link Cipher#ENCRYPT_MODE}, {@link Cipher#DECRYPT_MODE},
   *          {@link Cipher#WRAP_MODE} or , {@link Cipher#UNWRAP_MODE} only permitted
   * @param iv initialization vector, <code>null</code> not permitted or specification with <code>null</code>
   *          or empty byte array as IV ({@link IvParameterSpec#getIV()}), only possible for ECB block mode
   * @param provider name of provider, <code>null</code> for wildcard
   * @throws IllegalArgumentException if at least one argument or combination of arguments not valid
   */
  private static void checkGetCipherArguments(String algorithm,
                                              SecretKey key,
                                              int mode,
                                              IvParameterSpec iv,
                                              String provider)
  {
    AssertUtil.notNullOrEmpty(algorithm, "algorithm");
    AssertUtil.notNull(key, "secret key");
    String[] transformationParts = getTransformationParts(algorithm);
    boolean ivRequired = true;
    if (transformationParts.length >= IDX_TRANSFORMATION_BLOCKMODE
        && CipherUtil.BLOCK_MODE_ECB.equals(transformationParts[IDX_TRANSFORMATION_BLOCKMODE]))
    {
      ivRequired = false;
    }
    if (ivRequired)
    {
      AssertUtil.notNull(iv, "Initialization Vector");
      AssertUtil.notNullOrEmpty(iv.getIV(), "Initialiation Vector Bytes");
    }
    String keyAlgorithm = transformationParts[IDX_TRANSFORMATION_ALGORITHM_NAME];
    if (ALGORITHM_AES.equals(keyAlgorithm) && ivRequired && iv.getIV().length != AES_IV_LENGTH)
    {
      throw new IllegalArgumentException("initialization vector length does not match AES expected length: "
                                         + AES_IV_LENGTH);
    }
    if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE && mode != Cipher.WRAP_MODE
        && mode != Cipher.UNWRAP_MODE)
    {
      throw new IllegalArgumentException("illegal mode: " + mode
                                         + ", Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE, Cipher.WRAP_MODE or Cipher.UNWRAP_MODE only permitted");
    }
    if (!algorithm.startsWith(key.getAlgorithm()))
    {
      throw new IllegalArgumentException("algorithm and algorithm of key does not match: " + algorithm + ", "
                                         + key.getAlgorithm());
    }
    if (provider != null && Security.getProvider(provider) == null)
    {
      throw new IllegalArgumentException("provider unknown: '" + provider + "'");
    }
  }

  /**
   * Performs simple checks for secret key as not <code>null</code> and algorithm is as expected.
   *
   * @param key key to check, <code>null</code> not permitted, only key of expected algorithm is permitted
   * @param algorithm expected algorithm, algorithm
   * @param keySizeList optional List of permitted key sizes
   * @throws IllegalArgumentException if key <code>null</code> or algorithm is not as expected, if List of
   *           permitted key sizes given length of is checked against List
   */
  private static void checkCipherKey(SecretKey key, String algorithm, List<Integer> keySizeList)
  {
    AssertUtil.notNull(key, "secret key");
    if (!algorithm.equals(key.getAlgorithm()))
    {
      throw new IllegalArgumentException("illegal algorithm, key for " + algorithm + " permitted only");
    }
    if (keySizeList != null && !keySizeList.contains(Integer.valueOf(key.getEncoded().length)))
    {
      throw new IllegalArgumentException("illegal size of, key of size " + keySizeList + " permitted only");
    }
  }

  /**
   * Perform simple checks for mode used for ciphering data.
   *
   * @param mode mode of Cipher, {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE} only permitted
   * @throws IllegalArgumentException if cipher mode not permitted
   */
  private static void checkCipherMode(int mode)
  {
    if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE)
    {
      throw new IllegalArgumentException("illegal mode: " + mode
                                         + ", Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE only permitted");
    }
  }

  /**
   * Constant of separator String for algorithm, block mode and padding at transformation: <tt>/</tt>.
   *
   * @see #getTransformationParts(String)
   */
  private static final String TRANSFORMATION_SEPARATOR = "/";

  /**
   * Constant of index for name of transformation at result of {@link #getTransformationParts(String)}:
   * <tt>0</tt>.
   *
   * @see #getTransformationParts(String)
   * @see #IDX_TRANSFORMATION_BLOCKMODE
   * @see #IDX_TRANSFORMATION_PADDING
   */
  private static final int IDX_TRANSFORMATION_ALGORITHM_NAME = 0;

  /**
   * Constant of index for block mode of transformation at result of {@link #getTransformationParts(String)}:
   * <tt>1</tt>.
   *
   * @see #getTransformationParts(String)
   * @see #IDX_TRANSFORMATION_ALGORITHM_NAME
   * @see #IDX_TRANSFORMATION_PADDING
   */
  private static final int IDX_TRANSFORMATION_BLOCKMODE = 1;

  /**
   * Constant of index for padding of transformation at result of {@link #getTransformationParts(String)}:
   * <tt>2</tt>.
   *
   * @see #getTransformationParts(String)
   * @see #IDX_TRANSFORMATION_ALGORITHM_NAME
   * @see #IDX_TRANSFORMATION_BLOCKMODE
   */
  private static final int IDX_TRANSFORMATION_PADDING = 2;

  /**
   * Constant of block mode ECB.
   */
  private static final String BLOCK_MODE_ECB = "ECB";

  /**
   * Gets the different parts of transformation specifications as used by JCE: algorithm name, block mode and
   * padding, e. g. 'DES/CBC/NoPadding'.
   *
   * @param transformation transformation, <code>null</code> or empty String not permitted, transformation
   *          expected as String containing as maximum the three parts for name of algorithm, block mode and
   *          padding separated by {@link #TRANSFORMATION_SEPARATOR}
   * @return parts of algorithms array, using indices {@link #IDX_TRANSFORMATION_ALGORITHM_NAME},
   *         {@link #IDX_TRANSFORMATION_BLOCKMODE} and {@link #IDX_TRANSFORMATION_PADDING}, some parts maybe
   *         <code>null</code>, if part not specified
   * @throws IllegalArgumentException if transformation is <code>null</code>, empty String or does contain too
   *           much parts
   * @see #TRANSFORMATION_SEPARATOR
   * @see #IDX_TRANSFORMATION_ALGORITHM_NAME
   * @see #IDX_TRANSFORMATION_BLOCKMODE
   * @see #IDX_TRANSFORMATION_PADDING
   */
  private static final String[] getTransformationParts(String transformation)
  {
    AssertUtil.notNullOrEmpty(transformation, "transformation");
    String[] tmp = transformation.split(TRANSFORMATION_SEPARATOR);
    String[] result = new String[IDX_TRANSFORMATION_PADDING + 1];
    if (tmp.length > IDX_TRANSFORMATION_PADDING + 1)
    {
      throw new IllegalArgumentException("transformation contains more parts as expected, maximum of parts is"
                                         + (IDX_TRANSFORMATION_PADDING + 1));
    }
    System.arraycopy(tmp, 0, result, 0, tmp.length);
    for ( int i = 0 ; i < result.length ; i++ )
    {
      if ("".equals(result[i]))
      {
        result[i] = null;
      }
    }
    return result;
  }

  /**
   * Encipher bytes of data with AES key.
   *
   * @param algorithm algorithm, <code>null</code> or empty String not permitted
   * @param key key, <code>null</code> not permitted, only AES keys permitted
   * @param iv initialization vector, <code>null</code> not permitted or specification with <code>null</code>
   *          or empty byte array as IV ({@link IvParameterSpec#getIV()})
   * @param data bytes to be deciphered
   * @param provider name of provider, <code>null</code> for wildcard
   * @return deciphered bytes
   * @throws IllegalArgumentException if algorithm, key, mode or initialization vector not permitted,
   *           algorithm, key or parameters not supported
   * @throws BadPaddingException if block not padded correctly
   * @throws IllegalBlockSizeException if length of bytes-array is not multiple of AES key size (16 byte for
   *           128 bit, 24 byte for 192 bit and 32 byte for 256 bit)
   * @see #decipherAES(String, SecretKey, IvParameterSpec, byte[], String)
   * @see #cipherAES(String, SecretKey, int, IvParameterSpec, byte[], String)
   * @see Cipher#ENCRYPT_MODE
   */
  public static final byte[] encipherAES(String algorithm,
                                         SecretKey key,
                                         IvParameterSpec iv,
                                         byte[] data,
                                         String provider)
    throws IllegalBlockSizeException, BadPaddingException
  {
    return cipherAES(algorithm, key, Cipher.ENCRYPT_MODE, iv, data, provider);
  }

  /**
   * Decipher bytes of data with AES key.
   *
   * @param algorithm algorithm, <code>null</code> or empty String not permitted
   * @param key key, <code>null</code> not permitted, only AES keys permitted
   * @param iv initialization vector, <code>null</code> not permitted or specification with <code>null</code>
   *          or empty byte array as IV ({@link IvParameterSpec#getIV()})
   * @param data bytes to be deciphered
   * @param provider name of provider, <code>null</code> for wildcard
   * @return deciphered bytes
   * @throws IllegalArgumentException if algorithm, key, mode or initialization vector not permitted,
   *           algorithm, key or parameters not supported
   * @throws BadPaddingException if block not padded correctly
   * @throws IllegalBlockSizeException if length of bytes-array is not multiple of AES key size (16 byte for
   *           128 bit, 24 byte for 192 bit and 32 byte for 256 bit)
   * @see #encipherAES(String, SecretKey, IvParameterSpec, byte[], String)
   * @see #cipherAES(String, SecretKey, int, IvParameterSpec, byte[], String)
   * @see Cipher#DECRYPT_MODE
   */
  public static final byte[] decipherAES(String algorithm,
                                         SecretKey key,
                                         IvParameterSpec iv,
                                         byte[] data,
                                         String provider)
    throws IllegalBlockSizeException, BadPaddingException
  {
    return cipherAES(algorithm, key, Cipher.DECRYPT_MODE, iv, data, provider);
  }

  /**
   * Encipher/Decipher bytes of data with AES key.
   *
   * @param algorithm algorithm, <code>null</code> or empty String not permitted
   * @param key key, <code>null</code> not permitted, only AES keys permitted
   * @param mode mode of Cipher, {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE} only permitted
   * @param iv initialization vector, <code>null</code> not permitted or specification with <code>null</code>
   *          or empty byte array as IV ({@link IvParameterSpec#getIV()})
   * @param data bytes to be enciphered/deciphered, multiple of 8 bytes
   * @param provider name of provider, <code>null</code> for wildcard
   * @return enciphered/deciphered bytes
   * @throws IllegalArgumentException if algorithm, key, mode or initialization vector not permitted,
   *           algorithm, key or parameters not supported
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  private static final byte[] cipherAES(String algorithm,
                                        SecretKey key,
                                        int mode,
                                        IvParameterSpec iv,
                                        byte[] data,
                                        String provider)
    throws IllegalBlockSizeException, BadPaddingException
  {
    checkCipherKey(key, ALGORITHM_AES, KEY_SIZES_LIST_AES);
    checkCipherMode(mode);
    Cipher cipher = getCipher(algorithm, key, mode, iv, provider);
    return cipher.doFinal(data);
  }

  /**
   * Calculates CMAC of data (used for smartcards with AES based Secure messaging).
   *
   * @param bytes bytes to calculate checksum, <code>null</code> not permitted, empty array permitted,
   *          byte-array not multiple of AES block size permitted
   * @param macKey key for MAC calculation, <code>null</code> or other than AES key not permitted
   * @param iv initialization vector for calculation, <code>null</code> not permitted or specification with
   *          <code>null</code> or empty byte array as IV ({@link IvParameterSpec#getIV()})
   * @param outputLength optional output length ({@link #AES_CMAC_MINIMUM_LENGTH} to
   *          {@value #AES_CMAC_MAXIMUM_LENGTH} bytes possible), <code>null</code> to use default
   *          {@link #AES_CMAC_DEFAULT_LENGTH}
   * @return calculated checksum (CMAC as requested {@link #AES_CMAC_MINIMUM_LENGTH} to
   *         {@value #AES_CMAC_MAXIMUM_LENGTH} bytes)
   * @throws IllegalArgumentException if bytes, key or initialization vector invalid, also fails if padding
   *           not specified and passed bytes not externally padded to AES block size
   */
  public static final byte[] cMAC(byte[] bytes, SecretKey macKey, IvParameterSpec iv, Integer outputLength)
  {
    AssertUtil.notNull(bytes, "data");
    AssertUtil.notNull(macKey, "MAC key");
    AssertUtil.notNull(iv, "initialization vector");
    if (!CipherUtil.ALGORITHM_AES.equals(macKey.getAlgorithm()))
    {
      throw new IllegalArgumentException("only AES key permitted for MAC calculation");
    }

    byte[] ivBytes = iv.getIV();
    AssertUtil.notNullOrEmpty(ivBytes, "initialization vector bytes");
    if (ivBytes.length != AES_IV_LENGTH)
    {
      throw new IllegalArgumentException("initialization vector length not as expected: " + AES_IV_LENGTH
                                         + ", length found is " + ivBytes.length);
    }
    byte[] macData = ByteUtil.combine(new byte[][]{ivBytes, bytes});
    return cMAC(macData, macKey, outputLength);
  }

  /**
   * Plain CMAC calculation without SSC operating on data with key only.
   *
   * @param bytes bytes to calculate checksum, <code>null</code> not permitted, empty array permitted,
   *          byte-array not multiple of AES block size permitted
   * @param macKey key for MAC calculation, <code>null</code> or other than AES key not permitted
   * @param outputLength optional output length ({@link #AES_CMAC_MINIMUM_LENGTH} to
   *          {@value #AES_CMAC_MAXIMUM_LENGTH} bytes possible), <code>null</code> to use default
   *          {@link #AES_CMAC_DEFAULT_LENGTH}
   * @return calculated checksum (CMAC as requested {@link #AES_CMAC_MINIMUM_LENGTH} to
   *         {@value #AES_CMAC_MAXIMUM_LENGTH} bytes)
   * @throws IllegalArgumentException if data <code>null</code> or empty, key invalid, output length not
   *           within borders
   * @see #AES_CMAC_MINIMUM_LENGTH
   * @see #AES_CMAC_DEFAULT_LENGTH
   * @see #AES_CMAC_MAXIMUM_LENGTH
   */
  public static final byte[] cMAC(byte[] bytes, SecretKey macKey, Integer outputLength)
  {
    AssertUtil.notNull(bytes, "data");
    AssertUtil.notNull(macKey, "MAC key");

    if (!CipherUtil.ALGORITHM_AES.equals(macKey.getAlgorithm()))
    {
      throw new IllegalArgumentException("only AES key permitted for MAC calculation");
    }
    Integer outputLengthInt = outputLength;
    if (outputLength == null)
    {
      outputLengthInt = AES_CMAC_DEFAULT_LENGTH;
    }
    else if (outputLength < AES_CMAC_MINIMUM_LENGTH)
    {
      throw new IllegalArgumentException("output length exceeds minimum of " + AES_CMAC_MINIMUM_LENGTH
                                         + " bytes");
    }
    else if (outputLength > AES_CMAC_MAXIMUM_LENGTH)
    {
      throw new IllegalArgumentException("output length exceeds maximum of " + AES_CMAC_MAXIMUM_LENGTH
                                         + " bytes");
    }

    BlockCipher bc = new AESEngine();
    Mac m = new CMac(bc, outputLengthInt * 8);
    m.init(new KeyParameter(macKey.getEncoded()));
    byte[] result = new byte[outputLengthInt];
    m.update(bytes, 0, bytes.length);
    m.doFinal(result, 0);
    return result;
  }
}
