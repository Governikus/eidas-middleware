/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1ChildUtil.getElements;
import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1InfoUtil.isConstructed;
import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1InfoUtil.isSequence;
import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1InfoUtil.isSet;
import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1InfoUtil.isUniversal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.constants.ByteConstants;

import lombok.extern.slf4j.Slf4j;


/**
 * Implementation of convenience methods for basic processing of ASN.1.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
@Slf4j
final class ASN1BaseUtil
{

  /**
   * Constructor.
   */
  private ASN1BaseUtil()
  {
    super();
  }

  /**
   * Gets length bytes for a value.
   *
   * @param value bytes of value, <code>null</code> not permitted
   * @return bytes of length, determined encoding, <code>null</code> if argument empty
   * @throws IllegalArgumentException if value <code>null</code>
   */
  static byte[] getLengthBytes(byte[] value)
  {
    if (value == null)
    {
      throw new IllegalArgumentException("value expected");
    }
    byte[] result = null;
    if (value.length < 127)
    {
      result = new byte[]{(byte)value.length};
    }
    else
    {
      byte[] tmpLengthBytes1 = BigInteger.valueOf(value.length).toByteArray();
      int offset = 0;
      if (tmpLengthBytes1[0] == 0x00)
      {
        offset = 1;
      }
      byte[] tmpLengthBytes2 = new byte[tmpLengthBytes1.length + 1 - offset];
      System.arraycopy(tmpLengthBytes1, offset, tmpLengthBytes2, 1, tmpLengthBytes1.length - offset);
      tmpLengthBytes2[0] = (byte)(tmpLengthBytes1.length | 0x80);
      tmpLengthBytes2[0] -= tmpLengthBytes1[0] == 0x00 ? 1 : 0;
      result = tmpLengthBytes2;
    }
    return result;
  }

  /**
   * Gets length.
   *
   * @param bytesOfLength bytes of length, <code>null</code> or empty array not permitted
   * @return length
   * @throws IllegalArgumentException if length <code>null</code> or content of length of bytes does fits
   *           requirements of ASN.1 length encoding
   */
  static BigInteger toLength(byte[] bytesOfLength)
  {
    if (bytesOfLength == null || bytesOfLength.length == 0)
    {
      throw new IllegalArgumentException("bytes with length of ASN.1-structure expected");
    }
    if (bytesOfLength.length == 1 && bytesOfLength[0] == ASN1Constants.LENGTH_UNDETERMINED_BYTE)
    {
      return ASN1Constants.LENGTH_UNDETERMINED;
    }
    if (bytesOfLength.length == 1 && bytesOfLength[0] < 0)
    {
      throw new IllegalArgumentException("wrong length coding: one byte length, but more than one byte announced");
    }
    if (bytesOfLength[0] < 0 && ((bytesOfLength[0] & 0x7f) != bytesOfLength.length - 1))
    {
      throw new IllegalArgumentException("wrong length coding: number of bytes announced not matching number of bytes present");
    }
    if (bytesOfLength.length == 1 && bytesOfLength[0] > 0)// && bytesOfLength[0] <= 127)
    {
      return BigInteger.valueOf(bytesOfLength[0] & 0xff);
    }
    byte[] result = new byte[bytesOfLength.length];
    System.arraycopy(bytesOfLength, 0, result, 0, bytesOfLength.length);
    result[0] = 0x00;
    return new BigInteger(result);
  }

  /**
   * Gets bytes of value from stream for given bytes with description and tag and length.
   *
   * @param dTagBytes bytes with description and tag, <code>null</code> or empty array not permitted
   * @param length length, <code>null</code> not permitted
   * @param stream stream to read, <code>null</code> not permitted
   * @return bytes of value
   * @throws IOException if reading fails
   * @throws IllegalArgumentException if any parameter is <code>null</code> or dTagBytes is empty
   */
  static byte[] getBytesOfValue(byte[] dTagBytes, BigInteger length, InputStream stream) throws IOException
  {
    if (dTagBytes == null || dTagBytes.length == 0 || length == null || stream == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    byte[] result = null;
    if (length != ASN1Constants.LENGTH_UNDETERMINED)
    {
      result = getUndeterminedBytesInt(length, stream);
    }
    else
    {
      result = getDeterminedBytesInt(dTagBytes, stream);
    }
    return result;
  }

  private static byte[] getDeterminedBytesInt(byte[] dTagBytes, InputStream stream) throws IOException
  {
    byte[] result;
    // Sequence|Set|Constructed|Tagged
    if (isSequence(dTagBytes) || isSet(dTagBytes) || isConstructed(dTagBytes) || !isUniversal(dTagBytes))
    {
      ASN1[] asn1Values = getElements(stream, ASN1Constants.EOC_ASN1, false);
      result = encode(asn1Values);

    }
    else
    {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      int eocByteCounter = 0;
      int b = 0;
      byte[] eoc = ASN1Constants.EOC_ASN1.getEncoded();
      while (eocByteCounter < eoc.length && (b = stream.read()) != -1)
      {
        baos.write((byte)b);
        if (eocByteCounter == 0)
        {
          if (b == eoc[eocByteCounter])
          {
            eocByteCounter++;
          }
        }
        else
        {
          if (b == eoc[eocByteCounter])
          {
            eocByteCounter++;
          }
          else
          {
            eocByteCounter = 0;
          }
        }
      }
      baos.flush();
      baos.close();
      if (eocByteCounter != ASN1Constants.EOC_ASN1.getEncoded().length)
      {
        throw new IOException("insufficient data: EOC bytes not found");
      }
      result = baos.toByteArray();
    }
    return result;
  }

  private static byte[] getUndeterminedBytesInt(BigInteger length, InputStream stream) throws IOException
  {
    byte[] result;
    int modBufferLength = length.mod(ASN1Constants.BI_BUFFER_SIZE).intValue();
    int divBufferCount = length.divide(BigInteger.valueOf(4096)).intValue();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    int r = 0;
    byte[] buffer = new byte[ASN1Constants.BUFFER_SIZE];
    for ( int i = 0 ; i < divBufferCount ; i++ )
    {
      r = stream.read(buffer, 0, ASN1Constants.BUFFER_SIZE);
      baos.write(buffer, 0, r);
    }
    if (modBufferLength > 0)
    {
      int rSum = 0;
      int retries = 10;
      while (retries > 0 && modBufferLength != rSum)
      {
        r = stream.read(buffer, 0, modBufferLength);
        if (r != -1)
        {
          rSum += r;
          baos.write(buffer, 0, r);
        }
        else
        {
          retries -= 1;
        }
      }
      if (modBufferLength != rSum)
      {
        throw new IOException("insufficient data: " + (modBufferLength - rSum) + " byte more expected");
      }
    }
    baos.flush();
    baos.close();
    result = baos.toByteArray();
    return result;
  }

  /**
   * Appends hex-String representation of bytes to buffer using indents.
   *
   * @param buffer buffer, <code>null</code> not permitted
   * @param indent indent for byte-dump, <code>null</code> not permitted
   * @param bytes bytes to be encoded, <code>null</code> or empty array permitted
   * @throws IllegalArgumentException if buffer or indent <code>null</code>
   */
  static final void appendBytes(StringBuilder buffer, String indent, byte[] bytes)
  {
    if (buffer == null || indent == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_NOT_PERMITTED_AS_ARGUMENT);
    }
    String hex = Hex.hexify(bytes, " ");
    hex = hex.replaceAll("\n", "\n" + indent);
    buffer.append(indent + hex);
  }

  /**
   * Encodes array of ASN.1 objects.
   *
   * @param asn1s array of ASN.1 objects, <code>null</code> or empty array permitted (leading to empty result)
   * @return byte[]-array representation of ASN.1
   * @throws IOException if encoding fails
   */
  private static byte[] encode(ASN1[] asn1s) throws IOException
  {
    byte[] result = null;
    if (asn1s != null && asn1s.length > 0)
    {

      try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
      {
        for ( ASN1 asn1 : asn1s )
        {
          baos.write(asn1.getEncoded());
        }
      }
      catch (Exception e)
      {
        if (log.isDebugEnabled())
        {
          log.debug("Error encoding ASN1", e);
        }
        result = new byte[0];
      }
    }
    else
    {
      result = new byte[0];
    }
    return result;
  }

  /**
   * Gets bytes of description and tag from stream - bytes of description and tag includes bit encoded
   * informations about ASN.1 object.
   *
   * @param stream stream, <code>null</code> not permitted
   * @return byte[]-array of description and tag
   * @throws IOException if reading of stream fails
   * @throws IllegalArgumentException if stream <code>null</code>
   * @see ASN1Constants#TAG_BITS_FIRST_BYTE_MASK
   */
  static byte[] getDTagBytes(InputStream stream) throws IOException
  {
    if (stream == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_NOT_PERMITTED_AS_ARGUMENT);
    }
    byte[] result = null;
    int tag1 = stream.read();
    if (tag1 < 0)
    {
      throw new IOException("end of stream reached");
    }
    if ((tag1 & ASN1Constants.TAG_BITS_FIRST_BYTE_MASK) == ASN1Constants.TAG_BITS_FIRST_BYTE_MASK)
    {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      baos.write((byte)tag1);
      tag1 = stream.read();
      baos.write((byte)tag1);
      if (tag1 >= 128)
      {
        while ((tag1 = stream.read()) >= 128)
        {
          baos.write((byte)tag1);
        }
        baos.write((byte)tag1);
      }
      baos.flush();
      baos.close();
      result = baos.toByteArray();
    }
    else
    {
      result = new byte[]{(byte)tag1};
    }
    return result;
  }

  /**
   * Gets bytes of length from stream.
   *
   * @param stream stream, <code>null</code> not permitted
   * @return byte[]-array of length
   * @throws IOException if reading of stream fails
   * @throws IllegalArgumentException if stream <code>null</code>
   * @see ASN1Constants#TAG_BITS_FIRST_BYTE_MASK
   */
  static byte[] getBytesOfLength(InputStream stream) throws IOException
  {
    if (stream == null)
    {
      throw new IllegalArgumentException("null nor permitted");
    }
    byte[] result = null;
    int length = stream.read();
    // short format, length < 128
    if (length < 0)
    {
      throw new IOException("end of stream reached");
    }
    if (length < 128)
    {
      result = new byte[]{(byte)length};
    }
    // long format with leading 0x00 bytes == 129
    else if (length == 129)
    {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      baos.write((byte)length);
      length = length & 0x7f;

      for ( int i = 0 , n = length ; i < n ; i++ )
      {
        length = stream.read();
        if (i == 0 && length == 0x00)
        {
          i--;
        }
        baos.write((byte)length);
      }
      baos.flush();
      baos.close();
      result = baos.toByteArray();
    }
    // long format (determined)
    else if (length > 128)
    {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      baos.write((byte)length);
      length = length & 0x7f;

      for ( int i = 0 , n = length ; i < n ; i++ )
      {
        length = stream.read();
        if (length < 0)
        {
          throw new IOException("end of stream reached");
        }
        baos.write((byte)length);
      }
      baos.flush();
      baos.close();
      result = baos.toByteArray();
    }
    // undetermined length format
    else if (length == 128)
    {
      result = new byte[]{(byte)length};
    }
    return result;
  }






  /**
   * Checks tag bytes are valid
   *
   * @param dTagBytes tag descriptor bytes (class and tag bits, etc.), <code>null</code> or empty not
   *          permitted, if all bits of {@link ASN1Constants#TAG_BITS_FIRST_BYTE_MASK} set at first byte, the
   *          following bytes building tag are only valid, if second byte up to next to last most significant
   *          bit set and not set at last byte, if not all bits of
   *          {@link ASN1Constants#TAG_BITS_FIRST_BYTE_MASK} tag bytes expected to consist out of exactly one
   *          byte
   * @return valid tag bytes, otherwise exception expected to be thrown
   * @throws IllegalArgumentException if tag bytes not valid, <code>null</code>, empty or tag bytes content
   */
  static byte[] checkTagBytes(byte[] dTagBytes)
  {
    AssertUtil.notNullOrEmpty(dTagBytes, "tag bytes");
    if (ByteUtil.areBitsSet(dTagBytes[0], ASN1Constants.TAG_BITS_FIRST_BYTE_MASK))
    {
      AssertUtil.greaterEquals(dTagBytes.length, 2, "tag bytes count");
      for ( int i = 1 ; i < dTagBytes.length ; i++ )
      {
        if (i == dTagBytes.length - 1 && ByteUtil.areBitsSet(dTagBytes[i], ByteConstants.MASK_BIT8))
        {
          throw new IllegalArgumentException("tag bytes not valid, most significant bit not expected to be set at last byte, but found: "
                                             + Hex.hexify(dTagBytes[i]));
        }
        else if (i != dTagBytes.length - 1 && !ByteUtil.areBitsSet(dTagBytes[i], ByteConstants.MASK_BIT8))
        {
          throw new IllegalArgumentException("tag bytes not valid, at all tag bytes from second up to next to last most significant bit expected to be set, but not found at byte index "
                                             + i + ": " + Hex.hexify(dTagBytes[i]));
        }
        else if ((dTagBytes[i] & ASN1Constants.TAG_BITS_MASK) == 0x00)
        {
          throw new IllegalArgumentException("tag bytes not valid, at all tag bytes from first up to last at least one bit expected to be set, but not found at byte index "
                                             + i + ": " + Hex.hexify(dTagBytes[i]));
        }
      }
    }
    else if (dTagBytes.length != 1)
    {
      throw new IllegalArgumentException("only one byte for tag permitted, because extended tag not indicated at first byte, tag bytes  not valid");
    }
    return dTagBytes;
  }



  /**
   * Extracts clean tag from bytes with description and tag of ASN.1 - including ASN.1 bit coded informations
   * about class and content.
   *
   * @param dTagBytes bytes of Description and Tag, <code>null</code> or empty array not permitted
   * @return tag
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or too short
   */
  static BigInteger extractTag(byte[] dTagBytes)
  {
    BigInteger result = null;
    if (dTagBytes == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_NOT_PERMITTED_AS_ARGUMENT);
    }
    if (dTagBytes.length < 1)
    {
      throw new IllegalArgumentException("tag descriptor bytes expected as array with at least 1 byte");
    }
    int offset = 0;
    if (dTagBytes[0] == 0x00 && dTagBytes.length > 1)
    {
      offset = 1;
    }
    byte firstTagByte = dTagBytes[offset];
    if ((firstTagByte & ASN1Constants.TAG_BITS_FIRST_BYTE_MASK) == ASN1Constants.TAG_BITS_FIRST_BYTE_MASK)
    {
      BigInteger tmp = BigInteger.valueOf(0);
      BigInteger tagBits = null;
      for ( int i = offset + 1 ; i < dTagBytes.length ; i++ )
      {
        tmp = tmp.shiftLeft(7);
        tagBits = BigInteger.valueOf(ASN1Constants.TAG_BITS_MASK & dTagBytes[i]);
        tmp = tmp.or(tagBits);
      }
      result = tmp;
    }
    else
    {
      if ((dTagBytes.length - offset) != 1)
      {
        throw new IllegalArgumentException("only 1 byte expected as tag descriptor bytes (leading null-byte ignored)");
      }
      result = BigInteger.valueOf(firstTagByte & ASN1Constants.TAG_BITS_MASK);
    }
    return result;
  }

}
