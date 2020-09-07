/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.model.signeddata;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;


/**
 * BlackList The Blacklist as defined in TR-03129, Appendix B.
 * <p>
 * Will parse a ASN1 structure and provide access to the parsed values.
 *
 * @author Thomas Chojecki
 * @author Alexander Funk
 * @author Hauke Mehrtens
 */
public class BlackList
{

  private static final String OID_BSI_DE = "0.4.0.127.0.7";

  private static final String OID_APPLICATION_EID = OID_BSI_DE + ".3" + ".2";

  private static final String OID_BLACK_LIST = OID_APPLICATION_EID + ".2";

  // Types that are returned from getType()
  /**
   * This type of blacklist contain the whole blacklist
   */
  public static final int TYPE_COMPLETE = 0;

  /**
   * This type of blacklist contain additional blacklist entries
   */
  public static final int TYPE_ADDED = 1;

  /**
   * This type of blacklist contains entries that might be remove
   */
  public static final int TYPE_REMOVED = 2;

  private int version;

  private int type;

  private byte[] listID;

  private List<BlackListDetails> blacklistDetails;

  /**
   * BlackList asn1 parser.
   * <p>
   * Parse the given asn1 structure and extract the BlackList informations.
   *
   * @param bytes is the asn1 structure
   * @throws IllegalArgumentException if the asn1 structure can't be parse.
   */
  public BlackList(byte[] bytes)
  {
    try
    {
      // The methods are called inn this was, so the garbage collector can throw away all the temporary
      // classes generated in these methods, otherwise the GC only throws away the classes in methods we left.
      parseBlkDetails(parseList((ASN1Sequence)getASN1InputStream(getSignedContent(bytes))));
    }
    catch (CMSException | IOException e)
    {
      throw new IllegalArgumentException(
                                         "Some problem occurred while parsing the blacklist. Is the list CMS signed?",
                                         e);
    }
    // Finished parsing the black list data. Check if informations are available

    if (getListID() == null)
    {
      throw new IllegalArgumentException("Could not find the List identifier in the asn1 structure."
                                         + "\n(Was the right asn1 structure used?)");
    }
    if (blacklistDetails == null)
    {
      throw new IllegalArgumentException("Could not create any black list details."
                                         + "\n(Was the right asn1 structure used?)");
    }
  }

  private byte[] getSignedContent(byte[] bytes) throws CMSException
  {
    CMSSignedData s = new CMSSignedData(bytes);

    if (!OID_BLACK_LIST.equals(s.getSignedContentTypeOID()))
    {
      throw new IllegalArgumentException("Found no single match for list object identifier: "
                                         + OID_BLACK_LIST);
    }
    return (byte[])s.getSignedContent().getContent();
  }

  private ASN1Primitive getASN1InputStream(byte[] object) throws IOException
  {
    try (ASN1InputStream asn1 = new ASN1InputStream(object, true))
    {
      return asn1.readObject();
    }
  }

  private ASN1SequenceParser parseList(ASN1Sequence sequence) throws IOException
  {
    int size = sequence.size();

    // if our sequence don't have 4 or 5 objects, we could not parse the list.
    if (size < 4 || size > 5)
    {
      throw new IOException("Invalid structure. We expect 4 or 5 elements, but we got " + size);
    }

    version = ((ASN1Integer)sequence.getObjectAt(0)).getValue().intValue();
    type = ((ASN1Integer)sequence.getObjectAt(1)).getValue().intValue();
    listID = ((ASN1OctetString)sequence.getObjectAt(2)).getOctets();
    ASN1Sequence seq;
    if (size == 5)
    {
      seq = (ASN1Sequence)sequence.getObjectAt(4);
    }
    else
    {
      seq = (ASN1Sequence)sequence.getObjectAt(3);
    }
    return seq.parser();
  }

  private void parseBlkDetails(ASN1SequenceParser parser) throws IOException
  {
    blacklistDetails = new LinkedList<>();
    for ( ASN1Encodable blacklistDetailObj = parser.readObject() ; blacklistDetailObj != null ; blacklistDetailObj = parser.readObject() )
    {
      blacklistDetails.add(new BlackListDetails(blacklistDetailObj.toASN1Primitive().getEncoded()));
    }
  }

  /**
   * Will return a list with BlackListDetails which provides the SectorID and the related SectorSpecificIDs.
   * Note this list is not a copy.
   *
   * @return A List with BlackListDetails.
   */
  public List<BlackListDetails> getBlacklistDetails()
  {
    if (blacklistDetails == null)
    {
      return new LinkedList<>();
    }
    else
    {
      return blacklistDetails;
    }
  }

  /**
   * Return the Blacklist version.
   * <p>
   * For more version details take a look at the static fields starting with VERSION.
   *
   * @return the version as int. Use the static fields to compare different versions.
   */
  public int getVersion()
  {
    return version;
  }

  /**
   * Return the Blacklist type
   * <p>
   * For more type details take a look at the static fields starting with TYPE.
   *
   * @return the type as int. Use the static fields to compare different types.
   */
  public int getType()
  {
    return type;
  }

  /**
   * Return the Blacklist ID.
   *
   * @return a byte[] with the Blacklist ID information.
   */
  public byte[] getListID()
  {
    if (listID == null)
    {
      return null;
    }
    else
    {
      return listID.clone();
    }
  }
}
