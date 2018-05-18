/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.sm;

import java.util.Arrays;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;



/**
 * Some convenience methods for Secure Messaging purposes.
 * 
 * @see SMConstants
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class SMUtil
{

  /**
   * Constructor.
   */
  private SMUtil()
  {
    super();
  }

  /**
   * Pads bytes with given lead byte and pad byte to multiple of block size.
   * 
   * @param bytes bytes to be padded, <code>null</code> or empty array not permitted
   * @param leadingPadByte leading pad byte
   * @param padByte padding byte
   * @param blocksize block size (related to used symmetric key and its algorithm, e. g. 8 for DES)
   * @return padded bytes
   * @throws IllegalArgumentException if bytes null or empty array
   */
  private static final byte[] pad(byte[] bytes, byte leadingPadByte, byte padByte, int blocksize)
  {
    AssertUtil.notNullOrEmpty(bytes, "bytes");
    int l = bytes.length % blocksize;
    // check padding required
    if (l == 0)
    {
      // on block padding required
      l = blocksize;
    }
    else
    {
      l = blocksize - l;
    }
    // create array
    byte[] padding = new byte[l];
    // fill in pad bytes
    Arrays.fill(padding, padByte);
    // set leading pad byte
    padding[0] = leadingPadByte;
    // combine bytes and padding to padded bytes
    return ByteUtil.combine(bytes, padding);
  }

  /**
   * Pads data with to multiple of block size according to ISO.
   * 
   * @param bytes bytes to be padded, <code>null</code> or empty array not permitted
   * @param blocksize block size (related to used symmetric key and its algorithm, e. g. 8 for DES)
   * @return ISO padded bytes
   * @see SMConstants
   * @see SMConstants#PAD_BYTE_LEADING_ISO
   * @see SMConstants#PAD_BYTE_DEFAULT
   * @throws IllegalArgumentException if bytes <code>null</code> or empty array
   */
  static final byte[] padISO(byte[] bytes, int blocksize)
  {
    return pad(bytes, SMConstants.PAD_BYTE_LEADING_ISO, SMConstants.PAD_BYTE_DEFAULT, blocksize);
  }

  /**
   * Unpads bytes with given leading pad byte, pad byte and block size.
   * 
   * @param paddedBytes bytes to be unpadded, <code>null</code> or empty array not permitted
   * @param leadingPadByte leading pad byte
   * @param padByte padding byte
   * @param blocksize block size (related to used symmetric key and its algorithm, e. g. 8 for DES)
   * @return unpadded bytes
   * @throws IllegalArgumentException if padded bytes invalid or unpadding not possible
   */
  private static final byte[] unpad(byte[] paddedBytes, byte leadingPadByte, byte padByte, int blocksize)
  {
    AssertUtil.notNullOrEmpty(paddedBytes, "padded bytes");
    // check unpadding is required
    int l = paddedBytes.length % blocksize;
    if (l != 0)
    {
      throw new IllegalArgumentException("bytes can not be unpadded, bytes does not match block size");
    }
    // gets index of padding start
    l = ByteUtil.lastIndexOf(paddedBytes, new byte[]{leadingPadByte});
    // checks unpadding possible
    if (l <= 0)
    {
      // no padding exists
      throw new IllegalArgumentException("bytes can not be unpadded, padding not found");
    }
    //
    if (paddedBytes.length - l > blocksize)
    {
      throw new IllegalArgumentException("bytes can not be unpadded, too much padding bytes");
    }
    byte[] paddingEnd = new byte[paddedBytes.length - l - 1];
    Arrays.fill(paddingEnd, padByte);
    if (!Arrays.equals(paddingEnd, ByteUtil.subbytes(paddedBytes, l + 1)))
    {
      throw new IllegalArgumentException("bytes can not be unpadded, bytes not padded correctly");
    }
    // unpad
    return ByteUtil.subbytes(paddedBytes, 0, l);
  }

  /**
   * Unpads bytes according to ISO.
   * 
   * @param paddedBytes bytes to be unpadded, <code>null</code> or empty array not permitted
   * @param blocksize block size (related to used symmetric key and its algorithm, e. g. 8 for DES)
   * @return unpadded bytes
   * @throws IllegalArgumentException if padded bytes invalid or unpadding not possible
   */
  static final byte[] unpadISO(byte[] paddedBytes, int blocksize)
  {
    return unpad(paddedBytes, SMConstants.PAD_BYTE_LEADING_ISO, SMConstants.PAD_BYTE_DEFAULT, blocksize);
  }
}
