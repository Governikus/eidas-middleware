/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;


/**
 * Implementation of convenience methods for analyzing ASN.1.
 * <p>
 * Notice: full support of ASN.1 encoding rules for tags with multiple bytes.
 * </p>
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
final class ASN1Util
{

  /**
   * Checks bytes of ASN.1 with description and tag define a sequence.
   * 
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return <code>true</code>, if sequence
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @see ASN1Constants#UNIVERSAL_TAG_SEQUENCE
   */
  static boolean isSequence(byte[] dTagBytes)
  {
    return ASN1InfoUtil.isSequence(dTagBytes);
  }

  /**
   * Checks bytes of ASN.1 with description and tag define a set.
   * 
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return <code>true</code>, if set
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @see ASN1Constants#UNIVERSAL_TAG_SET
   */
  static boolean isSet(byte[] dTagBytes)
  {
    return ASN1InfoUtil.isSet(dTagBytes);
  }

  /**
   * Checks bytes of ASN.1 with description and tag defines a universal tag.
   * 
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return <code>true</code>, if universal
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @see ASN1Constants#TAG_CLASS_UNIVERSAL
   * @see ASN1Constants#TAG_CLASS_MASK
   */
  static boolean isUniversal(byte[] dTagBytes)
  {
    return ASN1InfoUtil.isUniversal(dTagBytes);
  }

  /**
   * Checks bytes of ASN.1 with description and tag defines a application tag.
   * 
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return <code>true</code>, if application
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @see ASN1Constants#TAG_CLASS_APPLICATION
   * @see ASN1Constants#TAG_CLASS_MASK
   */
  static boolean isApplication(byte[] dTagBytes)
  {
    return ASN1InfoUtil.isApplication(dTagBytes);
  }

  /**
   * Checks bytes of ASN.1 with description and tag defines a context specific tag.
   * 
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return <code>true</code>, if application
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @see ASN1Constants#TAG_CLASS_CONTEXT_SPECIFIC
   * @see ASN1Constants#TAG_CLASS_MASK
   */
  static boolean isContextSpecific(byte[] dTagBytes)
  {
    return ASN1InfoUtil.isContextSpecific(dTagBytes);
  }

  /**
   * Checks bytes of ASN.1 with description and tag defines a private tag.
   * 
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return <code>true</code>, if private
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @see ASN1Constants#TAG_CLASS_PRIVATE
   * @see ASN1Constants#TAG_CLASS_MASK
   */
  static boolean isPrivate(byte[] dTagBytes)
  {
    return ASN1InfoUtil.isPrivate(dTagBytes);
  }

  /**
   * Checks bytes of ASN.1 with description and tag define a primitive.
   * 
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @return <code>true</code>, if primitive
   * @see ASN1Constants#TAG_PRIMITIVE_MASK
   */
  static boolean isPrimitive(byte[] dTagBytes)
  {
    return ASN1InfoUtil.isPrimitive(dTagBytes);
  }

  /**
   * Gets list of all child elements of an ASN.1
   * 
   * @param asn1 ASN.1, <code>null</code> not permitted
   * @return list ofchild elements
   * @throws IOException if value of ASN.1 contains inconsistent data
   * @throws IllegalArgumentException if asn1 <code>null</code>
   * @see #getElements(InputStream, boolean)
   * @see #isSequence(byte[])
   * @see #isConstructed(byte[])
   * @see #isSet(byte[])
   * @see #isUniversal(byte[])
   */
  static List<ASN1> getChildElementList(ASN1 asn1) throws IOException
  {
    return ASN1ChildUtil.getChildElementList(asn1);
  }

  /**
   * Filter array of child elements for elements with given tag.
   * 
   * @param asn1s array of ASN.1, <code>null</code> and empty array permitted
   * @param tag tag for filtering
   * @return filtered array of child elements, {@link ASN1Constants#EMPTY_ASN1_ARRAY} for no child element
   *         found with given tag
   */
  static ASN1[] filterByTag(ASN1[] asn1s, int tag)
  {
    return ASN1FilterUtil.filterByTag(asn1s, tag);
  }

  /**
   * Filter array of child elements for elements with given tag of tag with description and tag.
   * 
   * @param asn1s array of ASN.1, <code>null</code> and empty array permitted (leading to empty result)
   * @param dTag description and tag for filtering - including ASN.1 bit coded informations about class and
   *          content, <code>null</code> not permitted
   * @return filtered array of child elements, {@link ASN1Constants#EMPTY_ASN1_ARRAY} for no child element
   *         found with given tag
   * @throws IllegalArgumentException if dTag <code>null</code>
   * @see #filterByTagOfDTagBytes(ASN1[], byte[])
   */
  static ASN1[] filterByTagOfDTag(ASN1[] asn1s, BigInteger dTag)
  {
    return ASN1FilterUtil.filterByTagOfDTag(asn1s, dTag);
  }

  /**
   * Filter array of child elements for elements with given description and tag.
   * 
   * @param asn1Objects array of ASN.1, <code>null</code> and empty array permitted (leading to empty result)
   * @param dTag description and tag for filtering - including ASN.1 bit coded informations about class and
   *          content, <code>null</code> not permitted
   * @return filtered array of child elements, {@link ASN1Constants#EMPTY_ASN1_ARRAY} for no child element
   *         found with given tag
   * @throws IllegalArgumentException if dTag <code>null</code>
   * @see #filterByDTagBytes(ASN1[], byte[])
   */
  static ASN1[] filterByDTag(ASN1[] asn1Objects, BigInteger dTag)
  {
    return ASN1FilterUtil.filterByDTag(asn1Objects, dTag);
  }

  /**
   * Filter array of child elements for elements with given bytes of description and tag.
   * 
   * @param asn1s array of ASN.1, <code>null</code> and empty array permitted (leading to empty result)
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return filtered array of child elements, {@link ASN1Constants#EMPTY_ASN1_ARRAY} for no child element
   *         found with given tag
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   */
  static ASN1[] filterByDTagBytes(ASN1[] asn1s, byte[] dTagBytes)
  {
    return ASN1FilterUtil.filterByDTagBytes(asn1s, dTagBytes);
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
    return ASN1BaseUtil.getLengthBytes(value);
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
    return ASN1BaseUtil.toLength(bytesOfLength);
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
   * @see #getElements(InputStream)
   */
  static byte[] getBytesOfValue(byte[] dTagBytes, BigInteger length, InputStream stream)
    throws IOException
  {
    return ASN1BaseUtil.getBytesOfValue(dTagBytes, length, stream);
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
    return ASN1BaseUtil.getDTagBytes(stream);
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
    return ASN1BaseUtil.getBytesOfLength(stream);
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
    return ASN1BaseUtil.checkTagBytes(dTagBytes);
  }

  /**
   * Extracts clean tag from bytes with description and tag of ASN.1 - including ASN.1 bit coded informations
   * about class and content.
   * 
   * @param dTagBytes bytes of Description and Tag, <code>null</code> or empty array not permitted
   * @return tag
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or too short
   */
  static final BigInteger extractTag(byte[] dTagBytes)
  {
    return ASN1BaseUtil.extractTag(dTagBytes);
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
    ASN1BaseUtil.appendBytes(buffer, indent, bytes);
  }

  /**
   * Constructor.
   */
  private ASN1Util()
  {
    super();
  }

}
