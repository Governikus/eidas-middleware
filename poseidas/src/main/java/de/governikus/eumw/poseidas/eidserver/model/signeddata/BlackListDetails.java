/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;


/**
 * BlackListDetails. The BlacklistDetails as defined in TR-03129, Appendix B.
 *
 * @author Thomas Chojecki
 */
public class BlackListDetails
{

  private byte[] sectorID;

  private List<byte[]> sectorSpecificIDs = null;

  /**
   * @param bytes
   * @throws IOException
   */
  BlackListDetails(byte[] blackListDetails) throws IOException
  {
    // The methods are called inn this was, so the garbage collector can throw away all the temporary classes
    // generated in these methods, otherwise the GC only throws away the classes in methods we left.
    parseDetailList(parseDetails(getASN1InputStream(blackListDetails)));

    // Finished parsing BlackList, check if all is done
    if (sectorID == null || sectorSpecificIDs == null)
    {
      throw new IOException(
                            "Could not find any blacklistdetails in the asn1 structure. Was the right asn1 structure used?");
    }
  }

  private ASN1Primitive getASN1InputStream(byte[] object) throws IOException
  {
    try (ASN1InputStream asn1 = new ASN1InputStream(object, true))
    {
      return asn1.readObject();
    }
  }

  private ASN1SequenceParser parseDetails(ASN1Primitive obj) throws IOException
  {
    ASN1Sequence sequence = (ASN1Sequence)obj;
    int size = sequence.size();

    // if our sequence don't have 2 objects, we could not parse the list.
    if (size != 2)
    {
      throw new IOException("Invalid structure. We expect 2 elements, but we got " + size);
    }
    sectorID = ((ASN1OctetString)sequence.getObjectAt(0)).getOctets();

    ASN1Sequence seq = (ASN1Sequence)sequence.getObjectAt(1);
    ASN1SequenceParser parser = seq.parser();
    return parser;
  }

  private void parseDetailList(ASN1SequenceParser parser) throws IOException
  {
    sectorSpecificIDs = new LinkedList<>();
    ASN1Encodable blacklistDetailObj;
    while ((blacklistDetailObj = parser.readObject()) != null)
    {
      sectorSpecificIDs.add(((ASN1OctetString)blacklistDetailObj).getOctets());
    }
  }

  /**
   * Return the SectorID of the BlackListDetail.
   * <p>
   * The sector identifier SectorID <b>SHALL</b> be used to reference the public keys PK<sup>Revocation</sup>
   * and PK<sub>Sector</sub> using the service GetSectorPublicKey provides by the MBS and the DVs,
   * respectively. The format of the sector identifier is defined by the Black List provider, it is
   * <b>RECOMMENDED</b> to use a hash of the public key.
   *
   * @return The Revocation Sector
   */
  public byte[] getSectorID()
  {
    return sectorID.clone();
  }

  /**
   * Return the Sector Specific IDs.
   * <p>
   * All public keys in SectorSpecificIDs <b>SHALL</b> be contained as plain public key values, i.e. excluding
   * the domain parameters. For Elliptic Curve Public Keys, the uncompressed encoding <b>MUST</b> be used.
   *
   * @return A List with the transformed Restricted Identification public key
   *         PK<sub>ID</sub><sup>Revocation</sup>.
   */
  public List<byte[]> getSectorSpecificIDs()
  {
    return new LinkedList<>(sectorSpecificIDs);
  }
}
