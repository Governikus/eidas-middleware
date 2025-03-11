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

import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1InfoUtil.isConstructed;
import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1InfoUtil.isSequence;
import static de.governikus.eumw.poseidas.cardbase.asn1.ASN1InfoUtil.isSet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.Hex;
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation of convenience methods for children of ASN.1.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
@Slf4j
final class ASN1ChildUtil
{

  /**
   * Constructor.
   */
  private ASN1ChildUtil()
  {
    super();
  }



  /**
   * Gets list of all child elements of an ASN.1
   *
   * @param asn1 ASN.1, <code>null</code> not permitted
   * @return list ofchild elements
   * @throws IOException if value of ASN.1 contains inconsistent data
   * @throws IllegalArgumentException if asn1 <code>null</code>
   * @see #getElements(InputStream, boolean)
   * @see ASN1InfoUtil#isSequence(byte[])
   * @see ASN1InfoUtil#isConstructed(byte[])
   * @see ASN1InfoUtil#isSet(byte[])
   * @see ASN1InfoUtil#isUniversal(byte[])
   */
  static List<ASN1> getChildElementList(ASN1 asn1) throws IOException
  {
    if (asn1 == null)
    {
      throw new IllegalArgumentException(ASN1UtilConstants.ERROR_MESSAGE_NULL_NOT_PERMITTED_AS_ARGUMENT);
    }
    ASN1[] children = ASN1Constants.EMPTY_ASN1_ARRAY;
    byte[] tagDescriptorBytes = asn1.getDTagBytes();
    List<ASN1> result = new ArrayList<>();
    if (isSequence(tagDescriptorBytes) || isSet(tagDescriptorBytes) || isConstructed(tagDescriptorBytes))
    {
      byte[] valueBytes = asn1.getValue();
      byte[] tmp = valueBytes;
      if (valueBytes != null && valueBytes.length > 0 && valueBytes[0] == 0x00)
      {
        tmp = new byte[valueBytes.length - 1];
        System.arraycopy(valueBytes, 1, tmp, 0, tmp.length);
      }
      if (tmp != null)
      {
        ByteArrayInputStream bis = new ByteArrayInputStream(tmp);
        children = getElements(bis, true);
      }
    }
    if (children != null)
    {
      for ( ASN1 tmp : children )
      {
        if (tmp != null)
        {
          result.add(tmp);
        }
      }
    }
    return result;
  }

  /**
   * Gets all child elements of an ASN.1.
   *
   * @param stream stream with ASN.1, <code>null</code> permitted
   * @param close <code>true</code> for closing stream after reading, <code>false</code> otherwise
   * @return array with child elements, empty array if no elements found
   * @throws IOException if stream operations fail
   * @see #getElements(InputStream, ASN1, boolean)
   */
  private static ASN1[] getElements(InputStream stream, boolean close) throws IOException
  {
    return getElements(stream, null, close);

  }

  /**
   * Gets all child elements of an ASN.1.
   *
   * @param stream stream with ASN.1 (value part only), <code>null</code> permitted
   * @param endValue optional ASN.1 for end of child search, e. g. as {@link ASN1Constants#EOC_ASN1} in case
   *          of undetermined length encoding
   * @param close <code>true</code> for closing stream after reading, <code>false</code> otherwise
   * @return array with child elements, empty array if no elements found
   * @throws IOException if stream operations fail
   */
  static ASN1[] getElements(InputStream stream, ASN1 endValue, boolean close) throws IOException
  {
    List<ASN1> resultList = new ArrayList<>();
    boolean endValueFound = false;
    if (stream != null)
    {
      try
      {
        ASN1 tmp = null;
        while (stream.available() != 0)
        {
          tmp = new ASN1(stream, false);
          if (endValue != null && endValue.equals(tmp))
          {
            endValueFound = true;
            break;
          }
          resultList.add(tmp);
        }
      }
      catch (IOException e)
      {
        if (log.isDebugEnabled())
        {
          log.debug("Error reading stream", e);
        }
        resultList.clear();
      }
      finally
      {
        if (close)
        {
          stream.close();
        }
      }
    }
    if (endValue != null && !endValueFound)
    {
      throw new IOException("terminating end value not read from stream: "
                            + Hex.hexify(endValue.getEncoded()));
    }
    return resultList.toArray(new ASN1[resultList.size()]);
  }


}
