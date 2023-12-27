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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1TaggedObject;


/**
 * EIDAbstractASN1List Base Class for the Master-, Defect- and Blacklist.
 *
 * @author Alexander Funk
 * @author Ole Behrens
 */
public abstract class AbstractASN1List // ocard asn1
{

  private static final Log LOGGER = LogFactory.getLog(AbstractASN1List.class.getName());

  static final String OID_BSI_DE = "0.4.0.127.0.7";

  static final String OID_ICAO = "2.23.136";

  private final byte[] bytes;

  private final String identifier;

  private boolean catalogued;

  AbstractASN1List(byte[] bytes, String listType)
  {
    // Handle the bytes to be parsed
    if (bytes == null || bytes.length < 1)
    {
      throw new IllegalArgumentException("Byte array for list not allowed to be null or empty");
    }
    this.bytes = bytes.clone();

    // Check the type name for this list
    if (listType == null || listType.length() < 1)
    {
      throw new IllegalArgumentException("List type identifier is null or empty:" + " Cannot catalogue list");
    }
    identifier = listType;

    // Check if stream is available
    // Parse the data from stream
    try (ASN1InputStream asn1 = new ASN1InputStream(this.bytes))
    {
      ASN1Primitive readObject;
      // Try to parse down through the asn1 tree. Object to find is the root sequence
      while ((readObject = asn1.readObject()) instanceof ASN1Sequence)
      {
        parseDERSequence((ASN1Sequence)readObject);
      }
      if (!catalogued)
      {
        throw new IOException("Found no single match for list object identifier: " + identifier);
      }
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("Unable to parse data", e);
    }
  }

  /**
   * Get the byte array set for this object
   *
   * @return a copy of this byte array
   */
  public byte[] getEncoded()
  {
    return bytes.clone();
  }

  /**
   * Parse object until specific list entry point is reached
   *
   * @param obj to parse
   * @throws IOExceptions
   */
  private void parseDERSequence(ASN1Sequence obj) throws IOException
  {
    ASN1SequenceParser parser = obj.parser();
    List<String> identifiers = new ArrayList<>();
    for ( ASN1Encodable readObject ; (readObject = parser.readObject()) != null ; )
    {
      if (readObject instanceof ASN1ObjectIdentifier)
      {
        ASN1ObjectIdentifier listObjectIdentifier = (ASN1ObjectIdentifier)readObject;
        String identifierInList = listObjectIdentifier.getId();
        // Try to find the ObjectId for the list
        if (identifier.equals(identifierInList))
        {
          ASN1Primitive object = ((ASN1TaggedObject)parser.readObject()).getBaseObject().toASN1Primitive();
          parseList(object);
          catalogued = true;
          return;
        }
        else
        {
          identifiers.add(identifierInList);
        }
      }
      else
      {
        // For all other objects use the ASN1Encodable parser to get next sequence
        parseASN1Encodable(readObject);
      }
    }

    if (!identifiers.isEmpty() && LOGGER.isTraceEnabled())
    {
      StringBuilder finer = new StringBuilder("Found no match for list object identifier in this sequence: ");
      finer.append(identifier).append("\nIdentified others:");
      for ( String identifierInList : identifiers )
      {
        finer.append("  " + identifierInList);
      }
      LOGGER.trace(finer.toString());
    }
  }


  /**
   * Parse all nonSequence-objects and try to get the next sequence
   *
   * @param obj to be parsed
   * @throws IOException
   */
  private void parseASN1Encodable(ASN1Encodable obj) throws IOException
  {
    obj = obj.toASN1Primitive();
    if (obj instanceof ASN1Sequence)
    {
      parseDERSequence((ASN1Sequence)obj);
    }
    else if (obj instanceof ASN1TaggedObject)
    {
      parseASN1Encodable(((ASN1TaggedObject)obj).getBaseObject());
    }
  }

  /**
   * Parse a ASN1Primitive to get informations depending on the list that is implemented
   *
   * @param object to be parsed
   * @throws IOException if parsing fails
   */
  public abstract void parseList(ASN1Primitive object) throws IOException;
}
