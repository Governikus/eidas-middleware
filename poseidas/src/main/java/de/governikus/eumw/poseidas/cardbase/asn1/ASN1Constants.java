/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import java.math.BigInteger;


/**
 * ASN.1-constants for usage in {@link ASN1} and {@link ASN1Util}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ASN1Constants
{

  /**
   * Constant of {@link ASN1#toString(boolean)} for full information including value.
   */
  public static final boolean FULL_FORMAT = true;

  /**
   * Constant of mask for tag class bits according to ASN.1 encoding rules.
   */
  public static final byte TAG_CLASS_MASK = (byte)0xc0;

  /**
   * Constant of mask for tag class bit indicating universal class according to ASN.1 encoding rules.
   */
  public static final byte TAG_CLASS_UNIVERSAL = (byte)0x00;

  /**
   * Constant of mask for tag class bit indicating application class according to ASN.1 encoding rules.
   */
  public static final byte TAG_CLASS_APPLICATION = (byte)0x40;

  /**
   * Constant of mask for tag class bit indicating context specific class according to ASN.1 encoding rules.
   */
  public static final byte TAG_CLASS_CONTEXT_SPECIFIC = (byte)0x80;

  /**
   * Constant of mask for tag class bit indicating private class according to ASN.1 encoding rules.
   */
  public static final byte TAG_CLASS_PRIVATE = (byte)0xc0;

  /**
   * Constant of mask for indicating primitive ASN.1.
   */
  public static final byte TAG_PRIMITIVE_MASK = (byte)0x20;

  /**
   * Constant of mask with significant bits of first bytes for tag.
   *
   * @see #TAG_BITS_MASK
   */
  public static final byte TAG_BITS_FIRST_BYTE_MASK = (byte)0x1f;

  /**
   * Constant of mask with significant bits of following bytes tag.
   *
   * @see #TAG_BITS_FIRST_BYTE_MASK
   */
  public static final byte TAG_BITS_MASK = (byte)0x7f;

  /**
   * Constant of tag for Printable String.
   */
  public static final byte UNIVERSAL_19_PRINTABLE_STRING = (byte)0x13;

  /**
   * Constant of tag for IA5 String.
   */
  public static final byte UNIVERSAL_22_IA5_STRING = (byte)0x16;

  /**
   * Constant of tag for UTF8-String.
   */
  public static final byte UTF8_STRING = (byte)0x0c;

  /**
   * Constant of tag for ASN.1-Integer.
   */
  public static final byte UNIVERSAL_TAG_INTEGER = (byte)0x02;

  /**
   * Constant of tag for ASN.1-OctetString.
   */
  public static final byte UNIVERSAL_TAG_OCTET_STRING = (byte)0x04;

  /**
   * Constant of tag for ASN.1-OID.
   */
  public static final byte UNIVERSAL_TAG_OID = (byte)0x06;

  /**
   * Constant of tag for ASN.1-Sequence (primitive).
   */
  public static final byte UNIVERSAL_TAG_SEQUENCE = (byte)0x10;

  /**
   * Constant of tag for ASN.1-Set (primitive).
   */
  public static final byte UNIVERSAL_TAG_SET = (byte)0x11;

  /**
   * Constant of tag for ASN.1-Sequence (constructed).
   *
   * @see #UNIVERSAL_TAG_SEQUENCE
   * @see #TAG_PRIMITIVE_MASK
   */
  public static final byte UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED = UNIVERSAL_TAG_SEQUENCE | TAG_PRIMITIVE_MASK;

  /**
   * Constant of tag for ASN.1-Set (constructed).
   *
   * @see #UNIVERSAL_TAG_SEQUENCE
   * @see #TAG_PRIMITIVE_MASK
   */
  public static final byte UNIVERSAL_TAG_SET_CONSTRUCTED = UNIVERSAL_TAG_SET | TAG_PRIMITIVE_MASK;

  /**
   * Constant of byte indicating undetermined length format - end of value indicated by EOC.
   *
   * @see #LENGTH_UNDETERMINED
   */
  public static final byte LENGTH_UNDETERMINED_BYTE = (byte)0x80;

  /**
   * Constant of length indicating undetermined length format.
   *
   * @see #LENGTH_UNDETERMINED_BYTE
   */
  public static final BigInteger LENGTH_UNDETERMINED = BigInteger.valueOf(-1);

  /**
   * Constant of ASN.1 with content EOC for search of value end at
   * {@link ASN1Util#getElements(java.io.InputStream, ASN1, boolean)}.
   */
  public static final ASN1 EOC_ASN1 = new ASN1(new byte[]{0x00}, new byte[]{0x00}, new byte[0], true);

  /**
   * Constant of buffer size for any reading of streams: <code>4096</code>.
   *
   * @see #BI_BUFFER_SIZE
   */
  public static final int BUFFER_SIZE = 4096;

  /**
   * Constant of buffer size for any reading of streams.
   *
   * @see #BUFFER_SIZE
   */
  public static final BigInteger BI_BUFFER_SIZE = BigInteger.valueOf(BUFFER_SIZE);

  /**
   * Constant of empty ASN.1-array.
   */
  public static final ASN1[] EMPTY_ASN1_ARRAY = new ASN1[0];

  private ASN1Constants()
  {}
}
