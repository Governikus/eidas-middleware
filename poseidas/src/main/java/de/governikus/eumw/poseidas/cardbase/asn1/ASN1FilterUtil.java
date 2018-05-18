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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.ByteUtil;


/**
 * Implementation of convenience methods for filtering ASN.1.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
final class ASN1FilterUtil
{

  /**
   * Constructor.
   */
  private ASN1FilterUtil()
  {
    super();
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
    return filterByTag(asn1s, (long)tag);
  }

  /**
   * Filter array of child elements for elements with given tag.
   * 
   * @param asn1s array of ASN.1, <code>null</code> and empty array permitted
   * @param tag tag for filtering
   * @return filtered array of child elements, {@link ASN1Constants#EMPTY_ASN1_ARRAY} for no child element
   *         found with given tag
   */
  private static ASN1[] filterByTag(ASN1[] asn1s, long tag)
  {
    ASN1[] lResult = ASN1Constants.EMPTY_ASN1_ARRAY;
    if (asn1s != null)
    {
      BigInteger tmpTag = BigInteger.valueOf(tag);
      List<ASN1> resultList = new ArrayList<>();
      for ( ASN1 asn1 : asn1s )
      {
        if (asn1 != null && asn1.getTag().equals(tmpTag))
        {
          resultList.add(asn1);
        }
      }
      lResult = resultList.toArray(new ASN1[resultList.size()]);
    }
    return lResult;
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
    if (dTag == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_NOT_PERMITTED_AS_ARGUMENT);
    }
    return filterByTagOfDTagBytes(asn1s, dTag.toByteArray());
  }

  /**
   * Filter array of child elements for elements with given tag of tag bytes with description and tag.
   * 
   * @param asn1s array of ASN.1, <code>null</code> and empty array permitted (leading to empty result)
   * @param dTagBytes bytes with description and tag of ASN.1 - including ASN.1 bit coded informations about
   *          class and content, <code>null</code> not permitted
   * @return filtered array of child elements, {@link ASN1Constants#EMPTY_ASN1_ARRAY} for no child element
   *         found with given tag
   * @throws IllegalArgumentException if dTagBytes <code>null</code>
   */
  private static ASN1[] filterByTagOfDTagBytes(ASN1[] asn1s, byte[] dTagBytes)
  {
    if (dTagBytes == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_NOT_PERMITTED_AS_ARGUMENT);
    }
    ASN1[] lResult = ASN1Constants.EMPTY_ASN1_ARRAY;
    if (asn1s != null)
    {
      BigInteger tag = ASN1Util.extractTag(dTagBytes);
      List<ASN1> resultList = new ArrayList<>();
      for ( ASN1 asn1 : asn1s )
      {
        if (asn1 != null && asn1.getTag().equals(tag))
        {
          resultList.add(asn1);
        }
      }
      lResult = resultList.toArray(new ASN1[resultList.size()]);
    }
    return lResult;
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
    if (dTag == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_NOT_PERMITTED_AS_ARGUMENT);
    }
    return filterByDTagBytes(asn1Objects, dTag.toByteArray());
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
    if (dTagBytes == null || dTagBytes.length == 0)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_OR_EMPTY_ARRAY_NOT_PERMITTED_AS_ARGUMENT);
    }
    byte[] tmpDTagBytes = dTagBytes;
    ASN1[] lResult = ASN1Constants.EMPTY_ASN1_ARRAY;
    // remove leading zero
    // remove leading zero bytes
    int i = 0;
    while (tmpDTagBytes[i] == 0)
    {
      i++;
    }
    tmpDTagBytes = ByteUtil.subbytes(ByteUtil.copy(tmpDTagBytes), i);
    if (asn1s != null)
    {
      List<ASN1> resultList = new ArrayList<>();
      for ( i = 0 ; i < asn1s.length ; i++ )
      {
        if (asn1s[i] != null && Arrays.equals(asn1s[i].getDTagBytes(), tmpDTagBytes))
        {
          resultList.add(asn1s[i]);
        }
      }
      lResult = resultList.toArray(new ASN1[resultList.size()]);
    }
    return lResult;
  }

}
