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

import de.governikus.eumw.poseidas.cardbase.constants.OIDConstants;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * The Block List as defined in TR-03129, Appendix B.
 * <p>
 * Will parse a ASN1 structure and provide access to the parsed values.
 *
 * @author Thomas Chojecki
 * @author Alexander Funk
 * @author Hauke Mehrtens
 */
@Getter
@Slf4j
public class BlackList
{

  /**
   * This type of block list contains the complete block list.
   */
  public static final int TYPE_COMPLETE = 0;

  /**
   * This type of block list is a delta list containing the added entries.
   */
  public static final int TYPE_ADDED = 1;

  /**
   * This type of block list is a delta list containing the removed entries.
   */
  public static final int TYPE_REMOVED = 2;

  /**
   * Version 1 of block list as per TR-03129 v1.10
   */
  public static final int VERSION_V1 = 0;

  /**
   * Version 2 of block list as per TR-03129 v1.40
   */
  public static final int VERSION_V2 = 1;

  private int version;

  private int type;

  private byte[] listID;

  // used only in delta list, null in complete list
  private byte[] deltaBase;

  // used only in delta list, null in complete list
  private Integer finalEntries;

  private List<BlackListDetails> blacklistDetails;

  /**
   * Block list asn1 parser.
   * <p>
   * Parse the given asn1 structure and extract the block list informations.
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
    catch (CMSException | IOException | ClassCastException e)
    {
      throw new IllegalArgumentException("Some problem occurred while parsing the block list. Is the list CMS signed?",
                                         e);
    }
  }

  private byte[] getSignedContent(byte[] bytes) throws CMSException
  {
    CMSSignedData s = new CMSSignedData(bytes);

    if (!OIDConstants.OID_BLOCKLIST.getOIDString().equals(s.getSignedContentTypeOID()))
    {
      throw new IllegalArgumentException("Found no match for list object identifier: "
                                         + OIDConstants.OID_BLOCKLIST.getOIDString());
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

    // if our sequence does not have 4 to 6 objects, it is no block list (see TR-03129 - v1 block list has 4 to 5
    // objects, v2 has 4 to 6).
    if (size < 4 || size > 6)
    {
      throw new IOException("Invalid structure. We expect 4 to 6 elements, but we got " + size);
    }

    // index 0 is always version
    version = ((ASN1Integer)sequence.getObjectAt(0)).getValue().intValue();
    if (version != VERSION_V1 && version != VERSION_V2)
    {
      throw new IOException("Unsupported block list version. Supported versions are " + VERSION_V1 + " and "
                            + VERSION_V2
                            + " but received " + version);
    }
    log.trace("Found block list version {}", version);

    // index 1 is always type
    type = ((ASN1Integer)sequence.getObjectAt(1)).getValue().intValue();
    if (type != TYPE_COMPLETE && type != TYPE_ADDED && type != TYPE_REMOVED)
    {
      throw new IOException("Unsupported block list type. Supported types are " + TYPE_COMPLETE + ", " + TYPE_ADDED
                            + " and " + TYPE_REMOVED + " but received " + type);
    }
    log.trace("Found block list type {}", type);

    // index 2 is always list ID
    listID = ((ASN1OctetString)sequence.getObjectAt(2)).getOctets();
    log.trace("Found block list ID {}", listID);

    // complete
    if (type == TYPE_COMPLETE)
    {
      ASN1Encodable object = sequence.getObjectAt(3);
      // in complete list, index 3 can be the list content...
      if (object instanceof ASN1Sequence seq)
      {
        return seq.parser();
      }
      // ...or the number of entries...
      finalEntries = ((ASN1Integer)object).getValue().intValue();
      log.trace("Found block list final number of entries {}", finalEntries);
      // ...followed by the list content at index 4
      return ((ASN1Sequence)sequence.getObjectAt(4)).parser();
    }

    // delta
    // in delta, index 3 is always delta base but Governikus DVCA has a defect causing this field to be missing...
    ASN1Encodable object = sequence.getObjectAt(3);
    int indexCorrection = 0;
    if (object instanceof ASN1OctetString os)
    {
      deltaBase = os.getOctets();
      log.trace("Found block list delta base {}", deltaBase);
    }
    // ...which is why we must work around this issue for the time being
    else
    {
      indexCorrection = -1;
    }

    if (version == VERSION_V1)
    {
      // in delta v1, index 4 is always list content
      return ((ASN1Sequence)sequence.getObjectAt(4 + indexCorrection)).parser();
    }

    // VERSION_V2
    // in delta v2, index 4 is always number of final entries
    finalEntries = ((ASN1Integer)sequence.getObjectAt(4 + indexCorrection)).getValue().intValue();
    log.trace("Found block list final number of entries {}", finalEntries);
    // in delta v2, index 5 is always list content
    return ((ASN1Sequence)sequence.getObjectAt(5 + indexCorrection)).parser();
  }

  private void parseBlkDetails(ASN1SequenceParser parser) throws IOException
  {
    blacklistDetails = new LinkedList<>();
    for ( ASN1Encodable blacklistDetailObj = parser.readObject() ; blacklistDetailObj != null ; blacklistDetailObj = parser.readObject() )
    {
      blacklistDetails.add(new BlackListDetails(blacklistDetailObj.toASN1Primitive().getEncoded()));
    }
  }
}
