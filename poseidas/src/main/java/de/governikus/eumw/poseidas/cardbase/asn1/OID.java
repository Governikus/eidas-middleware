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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.regex.Pattern;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;


/**
 * ASN.1 object for OID.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class OID extends AbstractASN1Encoder implements ASN1Encoder
{

  /**
   * Constant of factor for generating first byte of OID with first and second number of OID.
   */
  private static final int FIRST_ID_FACTOR = 40;

  /**
   * Constant of significant bits of OID byte.
   */
  private static final byte OTHER_ID_BIT_MASK = (byte)0x7f;

  /**
   * Constant of indicator for sequence of OID bytes.
   */
  private static final byte OTHER_ID_BYTE_SEQUENCE = (byte)0x80;

  /**
   * Constant of shift left to calculate OID number from sequence of OID bytes.
   */
  private static final byte OTHER_ID_LEFT_SHIFT = 7;

  // String for OID
  private String oidString;

  /**
   * Default Encoder Constructor.
   *
   * @throws IOException if parsing fails
   */
  public OID() throws IOException
  {
    super(new byte[]{ASN1Constants.UNIVERSAL_TAG_OID, 0x00});

  }

  /**
   * Constructor.
   *
   * @param oidString String representation, <code>null</code> or empty String not permitted, String
   *          containing only decimal digits and OID separator permitted
   * @see #toBytes(String)
   * @see AbstractASN1Encoder#AbstractASN1Encoder(byte, byte[])
   * @throws IllegalArgumentException if oidString <code>null</code> or empty
   */
  public OID(String oidString)
  {
    super(ASN1Constants.UNIVERSAL_TAG_OID, toBytes(oidString));
    this.oidString = oidString;
  }

  /**
   * Constructor.
   *
   * @param bytes bytes of ASN.1, tag must be {@link ASN1Constants#UNIVERSAL_TAG_OID}
   * @throws IOException if reading of stream fails
   * @throws IllegalArgumentException if tag not {@link ASN1Constants#UNIVERSAL_TAG_OID}
   * @see AbstractASN1Encoder#AbstractASN1Encoder(byte[])
   */
  public OID(byte[] bytes) throws IOException
  {
    super(AssertUtil.notNullOrEmpty(bytes, "bytes"));
    if (super.getTag().toByteArray().length != 1
        || super.getTag().toByteArray()[0] != ASN1Constants.UNIVERSAL_TAG_OID)
    {
      throw new IllegalArgumentException("illegal bytes, tag not OID tag byte 0x06");
    }
    this.oidString = toString(super.getValue());
  }

  /**
   * Gets String representation of OID.
   *
   * @return String representation
   */
  public String getOIDString()
  {
    return this.oidString;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return "OID: " + this.oidString;
  }

  /**
   * Constant of OID separator String: <tt>.</tt>.
   */
  private static final String OID_SEPARATOR = ".";

  /**
   * Convenience method to get bytes for OID String representation.
   *
   * @param oidString String representation, <code>null</code> or empty String not permitted, String
   *          containing only decimal digits and OID separator permitted
   * @return OID as byte[]-array
   * @throws IllegalArgumentException if oidString <code>null</code> or empty
   */
  private static byte[] toBytes(String oidString)
  {
    AssertUtil.notNullOrEmpty(oidString, "oidString");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    String[] digitStrings = oidString.split(Pattern.quote(OID_SEPARATOR));
    int[] digits = new int[digitStrings.length];
    for ( int i = 0 ; i < digitStrings.length ; i++ )
    {
      try
      {
        digits[i] = Integer.parseInt(digitStrings[i]);
      }
      catch (NumberFormatException nfe)
      {
        throw new IllegalArgumentException("illegal characters at OID String", nfe);
      }
    }
    for ( int i = 0 ; i < digits.length ; i++ )
    {
      if (i == 0)
      {
        baos.write((byte)(digits[0] * FIRST_ID_FACTOR + digits[++i]));
      }
      else
      {
        BigInteger bi = BigInteger.valueOf(digits[i]);
        StringBuilder bitStringBuilder = new StringBuilder();
        bitStringBuilder.append(bi.toString(2));
        while (bitStringBuilder.length() % 7 != 0)
        {
          bitStringBuilder.insert(0, '0');
        }
        for ( int j = 0 ; j < bitStringBuilder.length() ; j += 7 )
        {
          String tmp = bitStringBuilder.substring(j, j + 7);
          byte b = Byte.parseByte(tmp, 2);
          if (j < bitStringBuilder.length() - 8)
          {
            b |= OTHER_ID_BYTE_SEQUENCE;
          }
          baos.write(b);
        }
      }

    }
    return baos.toByteArray();
  }

  /**
   * Convenience method to get OID String representation for bytes of OID.
   *
   * @param oidValueBytes value bytes of an OID, <code>null</code> or empty array not permitted
   * @return OID String representation
   * @throws IllegalArgumentException if oidValueBytes <code>null</code> or empty
   */
  private static String toString(byte[] oidValueBytes)
  {
    AssertUtil.notNullOrEmpty(oidValueBytes, "value bytes");
    StringBuilder resultBuffer = new StringBuilder();
    resultBuffer.append((oidValueBytes[0] / FIRST_ID_FACTOR) + OID_SEPARATOR);
    resultBuffer.append((oidValueBytes[0] % FIRST_ID_FACTOR) + OID_SEPARATOR);
    int tmp = 0;
    for ( int i = 1 ; i < oidValueBytes.length ; i++ )
    {
      tmp |= (oidValueBytes[i] & OTHER_ID_BIT_MASK);
      if ((oidValueBytes[i] & OTHER_ID_BYTE_SEQUENCE) == OTHER_ID_BYTE_SEQUENCE)
      {
        tmp <<= OTHER_ID_LEFT_SHIFT;
      }
      else
      {
        resultBuffer.append(tmp);
        if (i < oidValueBytes.length - 1)
        {
          resultBuffer.append(OID_SEPARATOR);
        }
        tmp = 0;
      }
    }
    return resultBuffer.toString();
  }

  /** {@inheritDoc} */
  @Override
  public OID decode(ASN1 asn1)
  {
    if (asn1 == null)
    {
      return null;
    }
    super.copy(asn1);
    this.oidString = toString(super.getValue());
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode()
  {
    return super.hashCode();
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object obj)
  {
    return super.equals(obj);
  }

}
