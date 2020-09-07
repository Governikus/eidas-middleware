/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import de.governikus.eumw.poseidas.cardbase.constants.Constants;



/**
 * Implementation of byte[]-array wrapper and of convenience methods for creating or parsing hex-Strings.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class Hex
{

  private Hex()
  {}

  /**
   * Constant of empty HEX-String.
   *
   * @see Constants#EMPTY_STRING
   */
  private static final String EMPTY_HEXSTRING = Constants.EMPTY_STRING;

  /**
   * Constant of default indent - empty String.
   *
   * @see Constants#EMPTY_STRING
   * @see #dump(byte[])
   */
  private static final String DEFAULT_INDENT = Constants.EMPTY_STRING;

  /**
   * Constant of default bytes per line: <code>16</code>.
   *
   * @see #dump(byte[])
   */
  private static final int DEFAULT_LINE_SIZE = 16;

  /**
   * Hexify a byte value.
   *
   * @param value byte value
   * @return hex-String
   */
  public static final String hexify(byte value)
  {
    return hexify((int)value);
  }

  /**
   * Hexify an int value.
   *
   * @param value int value
   * @return hex-String
   */
  public static String hexify(int value)
  {
    return hexify(BigInteger.valueOf(value).toByteArray(), "");
  }

  /**
   * Hexify BigInteger.
   *
   * @param bi BigInteger
   * @return hex-String of BigInteger
   * @see #hexify(byte[])
   */
  public static final String hexify(BigInteger bi)
  {
    if (bi == null)
    {
      return EMPTY_HEXSTRING;
    }
    return hexify(bi.toByteArray());
  }

  /**
   * Hexifies byte[]-array.
   *
   * @param bytes bytes to hexified
   * @return hex-String of bytes
   * @see #hexify(byte[])
   */
  public static final String hexify(byte[] bytes)
  {
    return hexify(bytes, "");
  }

  /**
   * Hexifies byte[]-array.
   *
   * @param bytes bytes to hexified
   * @param separator separator String for hex representation, <code>null</code> or empty String permitted
   * @return hex-String of bytes
   * @see #hexify(byte[])
   */
  public static final String hexify(byte[] bytes, String separator)
  {
    if (bytes == null || bytes.length == 0)
    {
      return EMPTY_HEXSTRING;
    }
    StringBuilder tmpBuffer = new StringBuilder();
    tmpBuffer.append(new BigInteger(1, bytes).toString(16));
    int l = bytes.length * 2 - tmpBuffer.length();
    while (l-- > 0)
    {
      tmpBuffer.insert(0, "0");
    }
    if (separator == null || separator.length() == 0)
    {
      return tmpBuffer.toString();
    }
    StringBuilder resultBuffer = new StringBuilder();
    for ( int i = 0 ; i < tmpBuffer.length() ; i += 2 )
    {
      resultBuffer.append(tmpBuffer.substring(i, i + 2));
      resultBuffer.append(separator);
    }
    String result = resultBuffer.toString();
    return result.substring(0, result.length() - separator.length());
  }

  /**
   * Parses hex-String to bytes.
   *
   * @param hexString hex-String, <code>null</code> or empty String permitted
   * @return bytes of hex-String, empty array, if <code>null</code> or empty String permitted is parsed
   * @throws IllegalArgumentException if hexString has not even length
   */
  public static final byte[] parse(String hexString)
  {
    if (hexString == null || hexString.length() == 0)
    {
      return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
    String tmpHexString = cleanString(hexString);
    BigInteger resultBI = parseBigInteger(tmpHexString);
    byte[] tmp = null;
    if (resultBI == null)
    {
      return Constants.EMPTY_PRIMITIVE_BYTE_ARRAY;
    }
    byte[] resultBytes = resultBI.toByteArray();
    if (resultBytes.length >= 1 && resultBytes[0] == (byte)0x00 && !tmpHexString.startsWith("00")
        && resultBytes[1] < 0)
    {
      tmp = resultBytes;
      ByteBuffer bb = ByteBuffer.allocate(tmp.length - 1);
      bb.put(tmp, 1, tmp.length - 1);
      resultBytes = bb.array();
    }
    int byteResultLength = tmpHexString.length() / 2;
    int byteResultLengthDelta = byteResultLength - resultBytes.length;
    if (byteResultLengthDelta > 0)
    {
      ByteBuffer bb = ByteBuffer.allocate(byteResultLength);
      tmp = new byte[byteResultLengthDelta];
      Arrays.fill(tmp, (byte)0x00);
      bb.put(tmp);
      bb.put(resultBytes);
      resultBytes = bb.array();
    }
    return resultBytes;
  }

  /**
   * Parses hex-String into a BigInteger.
   *
   * @param hexString hex-String, <code>null</code> or empty String permitted, otherwise only Strings with
   *          even length permitted, line breaks or white spaces are ignored,
   * @return positive BigInteger, <code>null</code>, if String <code>null</code> or empty
   * @throws IllegalArgumentException if hexString has not even length
   */
  private static final BigInteger parseBigInteger(String hexString)
  {
    if (hexString == null || hexString.length() == 0)
    {
      return null;
    }
    String tmpHexString = cleanString(hexString);
    if (tmpHexString.length() % 2 != 0)
    {
      throw new IllegalArgumentException("String with hex representation expected as String with even length");
    }
    return new BigInteger(tmpHexString, 16);
  }

  /**
   * Removes blanks and returns from string.
   *
   * @param src string to be cleaned
   * @return cleaned string
   */
  private static String cleanString(String src)
  {
    String s1 = src.replace(" ", "");
    String s2 = s1.replace("\n", "");
    return s2.replace("\r", "");
  }

  /**
   * Dumps a String representation of bytes with default indent and bytes per line.
   *
   * @param data data to be dumped, <code>null</code> or empty array permitted
   * @return String representation with dump
   * @see #DEFAULT_INDENT
   * @see #DEFAULT_LINE_SIZE
   * @see #dump(String, byte[], int)
   */
  public static final String dump(byte[] data)
  {
    return dump(DEFAULT_INDENT, data, DEFAULT_LINE_SIZE);
  }

  /**
   * Dumps a String representation of bytes with given count of bytes for each line.
   *
   * @param indent indent for dump, <code>null</code> or empty String permitted
   * @param data data to be dumped, <code>null</code> or empty array permitted
   * @param lineSize bytes at each line of dump, size greater equals 1 only permitted
   * @return String representation with dump
   */
  private static final String dump(String indent, byte[] data, int lineSize)
  {
    if (lineSize < 1)
    {
      throw new IllegalArgumentException("size of line expected greater equals 1");
    }
    if (data == null || data.length == 0)
    {
      if (indent != null && indent.length() > 0)
      {
        return indent;
      }
      return "";
    }
    StringBuilder buffer = new StringBuilder();
    int count = 0;
    StringBuilder lineBytes = new StringBuilder();
    char[] filler = new char[lineSize * 3];
    Arrays.fill(filler, " ".charAt(0));
    for ( int i = 0 ; i <= data.length / lineSize ; i++ )
    {
      StringBuilder lineAsciiBuffer = new StringBuilder();
      lineBytes.setLength(0);
      if (indent != null && indent.length() > 0)
      {
        buffer.append(indent);
      }
      buffer.append(hexify(new byte[]{(byte)(count / 256)}));
      buffer.append(hexify(new byte[]{(byte)(count % 256)}));
      buffer.append(": ");
      for ( int j = 0 ; i * lineSize + j < data.length && j < lineSize ; j++ )
      {
        byte tmp = data[i * lineSize + j];
        lineBytes.append(hexify(tmp) + " ");
        if ((tmp >= 32) && (tmp < 127))
        {
          lineAsciiBuffer.append(new String(new byte[]{tmp}));
        }
        else
        {
          lineAsciiBuffer.append('.');
        }
      }
      buffer.append(lineBytes.toString());
      buffer.append(String.copyValueOf(filler, 0, (lineSize * 3) - lineBytes.length()));
      buffer.append("  " + lineAsciiBuffer.toString() + "\n");
      count += lineSize;
      if (count == data.length)
      {
        break;
      }
    }
    return buffer.toString();
  }
}
