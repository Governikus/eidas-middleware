/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1;

/**
 * Implementation of convenience methods for informations about ASN.1.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
final class ASN1InfoUtil
{

  /**
   * Constructor.
   */
  private ASN1InfoUtil()
  {
    super();
  }

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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return isUniversal(dTagBytes)
           && ((dTagBytes[0] & ASN1Constants.UNIVERSAL_TAG_SEQUENCE) == ASN1Constants.UNIVERSAL_TAG_SEQUENCE);
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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return isUniversal(dTagBytes)
           && ((dTagBytes[0] & ASN1Constants.UNIVERSAL_TAG_SET) == ASN1Constants.UNIVERSAL_TAG_SET);
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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return (dTagBytes[0] & ASN1Constants.TAG_CLASS_MASK) == ASN1Constants.TAG_CLASS_UNIVERSAL;
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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return (dTagBytes[0] & ASN1Constants.TAG_CLASS_MASK) == ASN1Constants.TAG_CLASS_APPLICATION;
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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return (dTagBytes[0] & ASN1Constants.TAG_CLASS_MASK) == ASN1Constants.TAG_CLASS_CONTEXT_SPECIFIC;
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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return (dTagBytes[0] & ASN1Constants.TAG_CLASS_MASK) == ASN1Constants.TAG_CLASS_PRIVATE;
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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return (dTagBytes[0] & ASN1Constants.TAG_PRIMITIVE_MASK) == 0;
  }

  /**
   * Checks bytes of ASN.1 with description and tag define a constructed.
   *
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> or empty array not permitted
   * @return <code>true</code>, if constructed
   * @throws IllegalArgumentException if dTagBytes <code>null</code> or empty
   * @see #isPrimitive(byte[])
   */
  static boolean isConstructed(byte[] dTagBytes)
  {
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    return !isPrimitive(dTagBytes);
  }


}
