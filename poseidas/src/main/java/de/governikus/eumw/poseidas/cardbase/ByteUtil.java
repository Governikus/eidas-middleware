/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.constants.ByteConstants;
import de.governikus.eumw.poseidas.cardbase.constants.Constants;


/**
 * Utilities for byte-arrays.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ByteUtil
{

  private static final String DEFAULT_MESSAGE_BYTE_ARRAY_NOT_PERMITTED_AS_NULL = "byte-array not permitted as null";

  /**
   * Constant to be used if the indexOf...-methods do not find anything.
   */
  private static final int INDEX_NOT_FOUND = -1;

  /**
   * Constructor.
   */
  private ByteUtil()
  {
    super();
  }

  /**
   * Combine two byte-arrays.
   *
   * @param bytes1 first byte-array, <code>null</code> or empty array permitted
   * @param bytes2 second byte-array, <code>null</code> or empty array permitted
   * @return new byte-array containing bytes of given byte-arrays
   */
  public static final byte[] combine(byte[] bytes1, byte[] bytes2)
  {
    if (bytes1 == null && bytes2 == null)
    {
      return null;
    }
    if (bytes1 == null)// && bytes2 != null)
    {
      if (bytes2.length != 0)
      {
        return copy(bytes2);
      }
      else
      {
        return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
      }
    }
    if (bytes2 == null)// && bytes1 != null)
    {
      if (bytes1.length != 0)
      {
        return copy(bytes1);
      }
      else
      {
        return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
      }
    }
    if (bytes1.length == 0 && bytes2.length == 0)
    {
      return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
    if (bytes1.length == 0)
    {
      return copy(bytes2);
    }
    if (bytes2.length == 0)
    {
      return copy(bytes1);
    }
    ByteBuffer buffer = ByteBuffer.allocate(bytes1.length + bytes2.length);
    buffer.put(bytes1);
    buffer.put(bytes2);
    return buffer.array();
  }

  /**
   * Combine multiple byte-arrays.
   *
   * @param bytes multiple byte-arrays, <code>null</code> or empty array permitted, <code>null</code> or empty array
   *          entries permitted
   * @return new byte-array containing bytes of given byte-arrays, <code>null</code> if array of arrays is
   *         <code>null</code> and {@link Constants#EMPTY_PRIMITIVE_BYTE_ARRAY} if result array is empty
   * @see #count(byte[][])
   */
  public static final byte[] combine(byte[][] bytes)
  {
    if (bytes == null)
    {
      return null;
    }
    if (bytes.length == 0)
    {
      return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
    int size = count(bytes);
    if (size == 0)
    {
      return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
    ByteBuffer buffer = ByteBuffer.allocate(size);
    for ( byte[] b : bytes )
    {
      if (b != null && b.length > 0)
      {
        buffer.put(b);
      }
    }
    return buffer.array();
  }

  /**
   * Copy byte-array.
   *
   * @param bytes byte-array
   * @return copied byte-array, <code>null</code> if byte-array <code>null</code> and
   *         {@link Constants#EMPTY_PRIMITIVE_BYTE_ARRAY} if byte-array empty
   * @see ByteBuffer#allocate(int)
   * @see ByteBuffer#put(byte[])
   * @see ByteBuffer#array()
   */
  public static final byte[] copy(byte[] bytes)
  {
    if (bytes == null)
    {
      return null;
    }
    if (bytes.length == 0)
    {
      return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
    ByteBuffer buffer = ByteBuffer.allocate(bytes.length);
    buffer.put(bytes);
    return buffer.array();
  }

  /**
   * Counts bytes of byte-arrays.
   *
   * @param bytes byte-arrays, <code>null</code> or <code>null</code> array entries are permitted
   * @return count of bytes of all byte-arrays
   */
  private static final int count(byte[][] bytes)
  {
    if (bytes == null)
    {
      return 0;
    }
    int size = 0;
    for ( byte[] b : bytes )
    {
      if (b != null && b.length > 0)
      {
        size += b.length;
      }
    }
    return size;
  }

  /**
   * Returns a new byte-array with a sub byte-array of given byte array beginning from given index to the end of the
   * array.
   * <p>
   * Notice: similar to {@link String#substring(int)}.
   * </p>
   *
   * @param bytes byte-array, <code>null</code> not permitted, empty array permitted
   * @param beginIndex index to begin sub array
   * @return new created byte-array with sub bytes of byte-array starting at given index
   * @see #subbytes(byte[], int, int)
   * @see String#substring(int)
   */
  public static final byte[] subbytes(byte[] bytes, int beginIndex)
  {
    if (bytes == null)
    {
      throw new IllegalArgumentException(DEFAULT_MESSAGE_BYTE_ARRAY_NOT_PERMITTED_AS_NULL);
    }
    return subbytes(bytes, beginIndex, bytes.length);
  }

  /**
   * Returns a new byte-array with a sub byte-array of given byte array between given begin and end index.
   * <p>
   * Notice: similar to {@link String#substring(int, int)}.
   * </p>
   *
   * @param bytes byte-array, <code>null</code> not permitted, empty array permitted
   * @param beginIndex index to begin sub array, value greater equals <code>0</code> and less equals length or array
   *          only permitted
   * @param endIndex index to end sub array, value greater equals <code>0</code> and less equals length or array only
   *          permitted, end index must be greater equals begin index
   * @return new created byte-array with sub bytes of byte-array, {@link Constants#EMPTY_PRIMITIVE_BYTE_ARRAY} if
   *         indices equals
   * @see Constants#EMPTY_PRIMITIVE_BYTE_ARRAY
   * @see String#substring(int, int)
   */
  public static final byte[] subbytes(byte[] bytes, int beginIndex, int endIndex)
  {
    if (bytes == null)
    {
      throw new IllegalArgumentException(DEFAULT_MESSAGE_BYTE_ARRAY_NOT_PERMITTED_AS_NULL);
    }
    if (beginIndex < 0)
    {
      throw new IllegalArgumentException("begin index only permitted greater equals 0");
    }
    if (endIndex < 0)
    {
      throw new IllegalArgumentException("end index only permitted greater equals 0");
    }
    if (beginIndex > bytes.length)
    {
      throw new IllegalArgumentException("begin index only permitted less equals length of array");
    }
    if (endIndex > bytes.length)
    {
      throw new IllegalArgumentException("end index only permitted less equals length of array");
    }
    if (beginIndex == bytes.length && endIndex != bytes.length)
    {
      throw new IllegalArgumentException("if begin index equals length of array, end index expected equals length of array only permitted");
    }
    if (endIndex < beginIndex)
    {
      throw new IllegalArgumentException("end index only permitted greater equals begin index");
    }
    if (endIndex == beginIndex)
    {
      return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
    ByteBuffer buffer = ByteBuffer.allocate(endIndex - beginIndex);

    buffer.put(bytes, beginIndex, endIndex - beginIndex);
    return buffer.array();
  }

  /**
   * Sets bits specified by mask at byte of byte-array specified by byte index.
   *
   * @param bytes byte-array, <code>null</code> or empty array not permitted
   * @param byteIndex index of byte, index greater equals <code>0</code> and less equals length of byte-array permitted
   * @param mask bit mask to set
   * @throws IllegalArgumentException if byte-array or byte index not permitted
   * @see #setBits(byte, byte)
   */
  public static final void setBits(byte[] bytes, int byteIndex, byte mask)
  {
    checkBytesAndByteIndex(bytes, byteIndex, true);
    bytes[byteIndex] = setBits(bytes[byteIndex], mask);
  }

  /**
   * Sets bits specified by mask at byte.
   *
   * @param b byte
   * @param mask bit mask
   * @return modified byte
   */
  private static final byte setBits(byte b, byte mask)
  {
    return (byte)(b | mask);
  }

  /**
   * Removes a leading zero from a byte array (used in case unsigned integer is requested).
   *
   * @param arg byte array to be converted, <code>null</code> or empty array not permitted
   * @return converted byte array, unchanged if first byte is not zero
   * @throws IllegalArgumentException if arg <code>null</code> or empty
   */
  public static byte[] removeLeadingZero(byte[] arg)
  {
    if (arg == null || arg.length == 0)
    {
      throw new IllegalArgumentException("null or empty array not permitted");
    }
    if (arg[0] != 0)
    {
      return arg;
    }
    return ByteUtil.subbytes(arg, 1);
  }

  /**
   * Adds a leading zero to a byte array (prevents values to be interpreted as negative).
   *
   * @param arg byte array to be converted, <code>null</code> or empty array permitted
   * @return new byte array with leading zero
   */
  public static byte[] addLeadingZero(byte[] arg)
  {
    if (arg == null || arg.length == 0)
    {
      throw new IllegalArgumentException("null or empty array not permitted");
    }
    if (arg[0] == 0)
    {
      return arg;
    }
    return ByteUtil.combine(new byte[]{0}, arg);
  }

  /**
   * XOR of byte-array with byte-array mask.
   *
   * @param bytes byte-array, <code>null</code> not permitted, empty array permitted
   * @param mask byte-array with xor-bytes, <code>null</code> or empty array permitted
   * @return new created byte-array with xor masked bytes, copy of byte if
   * @throws IllegalArgumentException if byte-array <code>null</code>
   * @see #xorBits(byte, byte)
   * @see #copy(byte[])
   */
  public static byte[] xorBits(byte[] bytes, byte[] mask)
  {
    if (bytes == null)
    {
      throw new IllegalArgumentException("byte[]-array not permitted as null for xor");
    }
    if (mask == null || mask.length == 0)
    {
      return copy(bytes);
    }
    byte[] result = new byte[bytes.length];
    for ( int i = 0 ; i < result.length ; i++ )
    {
      result[i] = xorBits(bytes[i], mask[i % mask.length]);
    }
    return result;
  }

  /**
   * XOR of bits specified by mask for byte.
   *
   * @param b byte
   * @param mask bit mask
   * @return modified byte
   */
  private static byte xorBits(byte b, byte mask)
  {
    return (byte)(b ^ mask);
  }

  /**
   * Returns a byte-array which is the result of a shift left operation (one step) on the input.
   *
   * @param input array to be shifted, most significant byte at index 0, <code>null</code> or empty not permitted
   * @return shifted array (as a new array instance, input is unchanged)
   * @throws IllegalArgumentException if input <code>null</code> or empty
   */
  public static byte[] shiftLeft(byte[] input)
  {
    AssertUtil.notNullOrEmpty(input, "input array");
    byte[] result = ByteUtil.copy(input);
    boolean oldCarry = false;
    boolean carry = false;
    for ( int i = result.length - 1 ; i >= 0 ; i-- )
    {
      oldCarry = carry;
      if (ByteUtil.isBitSet(result[i], 7))
      {
        carry = true;
      }
      else
      {
        carry = false;
      }
      result[i] = (byte)(result[i] * 2 + (oldCarry ? 1 : 0));
    }
    return result;
  }

  /**
   * Searches for last occurence of search byte-array at byte-array from last index.
   * <p>
   * Notice: similar to {@link String#lastIndexOf(String)}.
   * </p>
   *
   * @param bytes byte-array to search, <code>null</code> or empty array permitted
   * @param search byte-array to find, <code>null</code> or empty array permitted
   * @return last index of byte-array or {@link #INDEX_NOT_FOUND} if not found, an empty array or <code>null</code> is
   *         found at passed index
   * @see #INDEX_NOT_FOUND
   * @see #lastIndexOf(byte[], byte[], int)
   * @see String#lastIndexOf(String)
   */
  public static final int lastIndexOf(byte[] bytes, byte[] search)
  {
    if (bytes == null)
    {
      return INDEX_NOT_FOUND;
    }
    return lastIndexOf(bytes, search, bytes.length);
  }

  /**
   * Searches for last occurence of search byte-array at byte-array from given index to the begin.
   * <p>
   * Notice: similar to {@link String#lastIndexOf(String, int)}.
   * </p>
   *
   * @param bytes byte-array to search, <code>null</code> or empty array permitted
   * @param search byte-array to find, <code>null</code> or empty array permitted
   * @param beginIndex index
   * @return last index of byte-array or {@link #INDEX_NOT_FOUND} if not found, an empty array or <code>null</code> is
   *         found at passed index
   * @see #INDEX_NOT_FOUND
   * @see String#lastIndexOf(String, int)
   */
  private static final int lastIndexOf(byte[] bytes, byte[] search, int beginIndex)
  {
    if (beginIndex < 0)
    {
      throw new IllegalArgumentException("index for search not permitted less than 0");
    }
    if (bytes != null && beginIndex > bytes.length)
    {
      throw new IllegalArgumentException("index for search not permitted greater equals than length of byte-array");
    }
    if (bytes == null)
    {
      return INDEX_NOT_FOUND;
    }
    if (search == null || search.length == 0)
    {
      return beginIndex;
    }
    if (bytes.length == 0 && search.length > 0)
    {
      return INDEX_NOT_FOUND;
    }
    if (bytes.length < search.length)
    {
      return INDEX_NOT_FOUND;
    }
    int result = INDEX_NOT_FOUND;
    for ( int i = Math.min(beginIndex, bytes.length - search.length) ; i >= 0 ; i-- )
    {
      result = i;
      for ( int j = 0 ; j < search.length ; j++ )
      {
        if (bytes[i + j] != search[j])
        {
          result = INDEX_NOT_FOUND;
          break;
        }
      }
      if (result != INDEX_NOT_FOUND)
      {
        break;
      }
    }
    return result;
  }

  /**
   * Checks all bits of mask are set at given byte.
   *
   * @param b byte
   * @param mask bit mask
   * @return <code>true</code>, if all bits set, <code>false</code> otherwise
   */
  public static final boolean areBitsSet(byte b, byte mask)
  {
    if (mask == ByteConstants.ZERO)
    {
      return false;
    }
    return mask == (byte)(b & mask);
  }

  /**
   * Fills array with fill byte between given indices.
   *
   * @param bytes byte-array, <code>null</code> not permitted, empty array permitted
   * @param fillByte fill byte
   * @param beginIndex index to start fill, index less equals than <code>0</code> not permitted, index greater than
   *          length of byte-array not permitted
   * @param endIndex index to end fill, index less equals than <code>0</code> not permitted, index greater than length
   *          of byte-array not permitted, if beginIndex equals length of byte-array only length of byte.array
   *          permitted, end index greater equals begin index permitted only
   * @throws IllegalArgumentException if byte-array <code>null</code>, indices not permitted
   */
  public static final void fill(byte[] bytes, byte fillByte, int beginIndex, int endIndex)
  {
    if (bytes == null)
    {
      throw new IllegalArgumentException(DEFAULT_MESSAGE_BYTE_ARRAY_NOT_PERMITTED_AS_NULL);
    }
    if (beginIndex < 0)
    {
      throw new IllegalArgumentException("begin index only permitted greater equals 0");
    }
    if (endIndex < 0)
    {
      throw new IllegalArgumentException("end index only permitted greater equals 0");
    }
    if (beginIndex > bytes.length)
    {
      throw new IllegalArgumentException("begin index only permitted less equals length of array");
    }
    if (endIndex > bytes.length)
    {
      throw new IllegalArgumentException("end index only permitted less equals length of array");
    }
    if (beginIndex == bytes.length && endIndex != bytes.length)
    {
      throw new IllegalArgumentException("if begin index equals length of array, end index expected equals length of array");
    }
    if (endIndex < beginIndex)
    {
      throw new IllegalArgumentException("end index only permitted greater equals begin index");
    }
    for ( int i = beginIndex ; i < endIndex ; i++ )
    {
      bytes[i] = fillByte;
    }
  }

  /**
   * Checks byte-array and index of byte.
   *
   * @param bytes byte-array, <code>null</code> or empty array not permitted
   * @param byteIndex index of byte, index greater equals <code>0</code> and less length of byte-array permitted or
   *          index greater equals <code>0</code> and less equals length of byte-array permitted according to
   *          lengthOfArrayExcluded value
   * @param lengthOfArrayExcluded <code>true</code>, if byte index less than length of array permitted,
   *          <code>false</code>, if byte index less equals length of array permitted
   * @throws IllegalArgumentException if byte-array or byte index not permitted
   */
  private static void checkBytesAndByteIndex(byte[] bytes, int byteIndex, boolean lengthOfArrayExcluded)
  {
    if (bytes == null || bytes.length == 0)
    {
      throw new IllegalArgumentException("byte-array not permitted as null or empty array");
    }
    if (byteIndex < 0)
    {
      throw new IllegalArgumentException("byte index not permitted less than 0");
    }
    if (lengthOfArrayExcluded)
    {
      if (byteIndex >= bytes.length)
      {
        throw new IllegalArgumentException("byte index not permitted greater equals length of array");
      }
      if (byteIndex > bytes.length)
      {
        throw new IllegalArgumentException("byte index not permitted greater length of array");
      }
    }
  }

  /**
   * Checks a single bit of given byte is set.
   *
   * @param b byte
   * @param index index of bit
   * @return <code>true</code>, if set, otherwise false
   * @throws IllegalArgumentException if index not permitted
   * @see #areBitsSet(byte, int[])
   * @see ByteConstants#MINIMUM_BIT_INDEX
   * @see ByteConstants#MAXIMUM_BIT_INDEX
   */
  public static final boolean isBitSet(byte b, int index)
  {
    return areBitsSet(b, new int[]{index});
  }

  /**
   * Checks all bits of indices array are set at given byte.
   *
   * @param b byte
   * @param indices indices of bits, <code>null</code> or empty array permitted, only indices between
   *          {@link ByteConstants#MINIMUM_BIT_INDEX} and {@link ByteConstants#MAXIMUM_BIT_INDEX} permitted
   * @return <code>true</code>, if all bits set, <code>false</code> otherwise
   * @throws IllegalArgumentException if indices array or at least one bit index is not permitted
   * @see #areBitsSet(byte, byte)
   * @see #createBitMask(int[])
   * @see ByteConstants#MINIMUM_BIT_INDEX
   * @see ByteConstants#MAXIMUM_BIT_INDEX
   */
  private static final boolean areBitsSet(byte b, int[] indices)
  {
    if (indices == null || indices.length == 0)
    {
      return false;
    }
    byte mask = createBitMask(indices);
    return areBitsSet(b, mask);
  }

  /**
   * Creates bit mask for a bit indices array.
   *
   * @param indices indices of bits, <code>null</code> not permitted, only indices between
   *          {@link ByteConstants#MINIMUM_BIT_INDEX} and {@link ByteConstants#MAXIMUM_BIT_INDEX} permitted
   * @return bit mask
   * @throws IllegalArgumentException if bit index not permitted
   * @see #createBitMask(int[])
   * @see ByteConstants#MINIMUM_BIT_INDEX
   * @see ByteConstants#MAXIMUM_BIT_INDEX
   * @see ByteConstants#BIT_INDEX_MASK_LIST
   */
  private static byte createBitMask(int[] indices)
  {
    if (indices == null)
    {
      throw new IllegalArgumentException("indices array not permitted as null");
    }
    byte mask = (byte)0x00;
    if (indices.length == 0)
    {
      return mask;
    }
    checkBitIndex(indices);
    List<Integer> indicesList = new ArrayList<>();
    for ( int i = 0 ; i < indices.length ; i++ )
    {
      if (!indicesList.contains(Integer.valueOf(indices[i])))
      {
        mask |= ByteConstants.BIT_INDEX_MASK_LIST.get(indices[i]).byteValue();
        indicesList.add(Integer.valueOf(indices[i]));
      }
    }
    return mask;
  }

  /**
   * Check array of bit indices - every index of bit must be between minimum 0 - {@link #MINIMUM_BIT_INDEX} and maximum
   * 7 - {@link ByteConstants#MINIMUM_BIT_INDEX}.
   *
   * @param indices bit indices
   * @throws IllegalArgumentException if one index not permitted
   * @see #checkBitIndex(int)
   * @see ByteConstants#MINIMUM_BIT_INDEX
   * @see ByteConstants#MAXIMUM_BIT_INDEX
   */
  private static void checkBitIndex(int[] indices)
  {
    if (indices == null || indices.length == 0)
    {
      return;
    }
    for ( int indice : indices )
    {
      checkBitIndex(indice);
    }
  }

  /**
   * Checks given index of bit must be between minimum 0 - {@link ByteConstants#MINIMUM_BIT_INDEX} and maximum 7 -
   * {@link ByteConstants#MINIMUM_BIT_INDEX}.
   *
   * @param index index of bit
   * @throws IllegalArgumentException if index not permitted
   * @see ByteConstants#MINIMUM_BIT_INDEX
   * @see ByteConstants#MAXIMUM_BIT_INDEX
   */
  private static void checkBitIndex(int index)
  {
    if (index < ByteConstants.MINIMUM_BIT_INDEX)
    {
      throw new IllegalArgumentException("index only permitted greater equals 0");
    }
    if (index > ByteConstants.MAXIMUM_BIT_INDEX)
    {
      throw new IllegalArgumentException("index only permitted less equals 7");
    }
  }

  /**
   * Trim byte array containing integer to required length (cutting or extending if required) without changing integer
   * value.
   *
   * @param tmp bytes to trim, <code>null</code> or empty not permitted
   * @param trimLen length to trim to, must be (tmp.length-1) or higher
   * @return trimmed bytes
   * @throws IllegalArgumentException if given bytes <code>null</code> or empty
   */
  public static byte[] trimByteArray(byte[] tmp, int trimLen)
  {
    AssertUtil.notNullOrEmpty(tmp, "byte array to trim");
    if (tmp.length > (trimLen + 1))
    {
      throw new IllegalArgumentException("removing more than one zero not supported");
    }
    byte[] result = tmp;
    if (tmp.length > trimLen)
    {
      // too long, so remove leading zeros (if there is one its only one from positive integer
      // representation)
      result = removeLeadingZero(tmp);
    }
    else if (tmp.length < trimLen)
    {
      // too short, so extend fill up at beginning with leading zeros, normally it should be also only one
      // but who knows, that should cover every case of too short byte-array at this place
      byte[] f = new byte[trimLen - tmp.length];
      ByteUtil.fill(f, (byte)0x00, 0, f.length);
      result = ByteUtil.combine(f, tmp);
    }
    return result;
  }

  /**
   * Check byte[]-array equals.
   *
   * @param bytes1 first byte[]-array, <code>null</code> or empty array permitted
   * @param bytes2 second byte[]-array, <code>null</code> or empty array permitted
   * @return <code>true</code> if equals, otherwise <code>null</code>
   */
  public static boolean equals(byte[] bytes1, byte[] bytes2)
  {
    return Arrays.equals(bytes1, bytes2);
  }

}
