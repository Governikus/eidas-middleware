/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;


/**
 * DefectList as defined in TR-03129, Appendix A.1. A List of unreliable NPAs
 * <p>
 * Defect list is defined as a BER encoded SignedData:<br />
 * o id-DefectList<br />
 * o DefectList<br />
 * <br />
 * where<br />
 * <code>DefectList ::= Sequence {<br />
  version INTEGER {v1(0)}<br />
  hashAlg OBJECT IDENTIFIER,<br />
  defects SET OF Defect <br />
}</code><br />
 *
 * @author Alexander Funk
 * @author Ole Behrens
 */
public class DefectList extends AbstractASN1List
{

  private static final Log LOGGER = LogFactory.getLog(DefectList.class.getName());

  private static final String OID_APPLICATION_MRTD = OID_BSI_DE + ".3" + ".1";

  protected static final String OID_DEFECT_LIST = OID_APPLICATION_MRTD + ".5";

  private static final String OID_HASH_SHA1 = "1.3.14.3.2.26";

  private static final String OID_HASH_SHA256 = "2.16.840.1.101.3.4.2.1";

  private static final int DEFECT_LIST_VERSION = 0;

  private int version;

  private String hashAlgorithm;

  private String hashAlgorithmOID;

  private List<Defect> defects;


  /**
   * Defect list object where the bytes are parsed implicit
   *
   * @param bytes representing the list
   */
  public DefectList(byte[] bytes)
  {
    super(bytes, OID_DEFECT_LIST);
  }


  @Override
  public void parseList(ASN1Primitive object) throws IOException
  {
    check();

    // Get the octets
    ASN1Primitive obj = null;
    // Create a new input stream for bytes representing defect list
    try (ASN1InputStream asn1 = new ASN1InputStream(object.getEncoded()))
    {
      obj = asn1.readObject();
    }
    ASN1OctetString dos = (ASN1OctetString)obj;
    byte[] octets = dos.getOctets();

    // New input stream to collect defects

    try (ASN1InputStream asn1 = new ASN1InputStream(octets))
    {
      obj = asn1.readObject();
      if (obj instanceof ASN1Sequence)
      {
        // Sequence representing the content type DefectList
        ASN1Sequence sequence = (ASN1Sequence)obj;
        int sequenceElements = sequence.size();
        if (sequenceElements < 3)
        {
          throw new IOException("Defect list cannot be set because ASN1 squence incomplete."
                                + "\n Need: version, hash algorithm and a set of defects");
        }
        for ( int i = 0 ; i < sequenceElements ; i++ )
        {
          ASN1Encodable objectAt = sequence.getObjectAt(i);

          // First element of sequence should be the version identifier
          if (objectAt instanceof ASN1Integer)
          {
            LOGGER.debug("{" + i + "} Get defect list version");
            ASN1Integer version = (ASN1Integer)objectAt;
            int value = version.getValue().intValue();
            if (value != DEFECT_LIST_VERSION)
            {
              LOGGER.warn("Defect list with unexpected version: " + value);
            }
            this.version = value;
          }

          // Second element of sequence should be an OID for hashAlg
          else if (objectAt instanceof ASN1ObjectIdentifier)
          {
            LOGGER.debug("{" + i + "} Get defect list hash algorithm");
            ASN1ObjectIdentifier hashAlg = (ASN1ObjectIdentifier)objectAt;
            hashAlgorithmOID = hashAlg.getId();
            if (hashAlgorithmOID.equals(OID_HASH_SHA1))
            {
              hashAlgorithm = "SHA1";
            }
            else if (hashAlgorithmOID.equals(OID_HASH_SHA256))
            {
              hashAlgorithm = "SHA256";
            }
            else
            {
              LOGGER.warn("Unknown hash algorithm: " + hashAlgorithmOID + "(OID)");
              hashAlgorithm = hashAlgorithmOID;
            }
          }

          // Third element of sequence should be a set of defects
          else if (objectAt instanceof ASN1Set)
          {
            LOGGER.debug("{" + i + "} Get defects");
            ASN1Set set = (ASN1Set)objectAt;
            LOGGER.debug("Collecting (" + set.size() + ") defect(s)");
            for ( int j = 0 ; j < set.size() ; j++ )
            {
              ASN1Encodable defectSequence = set.getObjectAt(j);
              if (defectSequence instanceof ASN1Sequence)
              {
                Defect defect = new Defect((ASN1Sequence)defectSequence);
                defects.add(defect);
              }
              else
              {
                LOGGER.debug("Unexpected element in sequence");
              }
            }
          }

          // Unknown elements
          else
          {
            LOGGER.debug("Unknown element in sequence: " + objectAt);
          }
        }
      }
    }
  }

  /**
   * Indicates if defect exists for the identifier
   *
   * @param identifier to check
   * @return true if existing
   */
  public boolean containDefectsForCard(IssuerAndSerialNumber identifier)
  {
    if (getDefects(identifier).isEmpty())
    {
      return false;
    }
    else
    {
      return true;
    }
  }


  /**
   * Returning all defects found in list structure
   *
   * @return defects as a list
   */
  public List<Defect> getDefects()
  {
    check();
    return new ArrayList<>(defects);
  }


  /**
   * Get a defect for an issuer and serial number
   *
   * @param identifier to be found in list
   * @return a defect if found
   */
  public List<Defect> getDefects(IssuerAndSerialNumber identifier)
  {
    List<Defect> defects = new ArrayList<>();
    for ( Defect defect : this.defects )
    {
      if (defect.containsIssuerAndSerialNumber())
      {
        IssuerAndSerialNumber signerDocumentIdentifier = defect.getSignerDocumentIdentifier();
        if (identifier.equals(signerDocumentIdentifier))
        {
          defects.add(defect);
        }
      }
    }
    return defects;
  }

  /**
   * Get the version of this defect list
   *
   * @return number as integer
   */
  public int getListVersion()
  {
    return version;
  }

  /**
   * To be able to check the signer document for defects the hash algorithm must be known
   *
   * @return name as string
   */
  public String getListHashAlgorithmName()
  {
    return hashAlgorithm;
  }

  /**
   * OID for hash algorithm for the signer document
   *
   * @return OID as string
   */
  public String getListHashAlgorithmOID()
  {
    return hashAlgorithmOID;
  }

  /**
   * Get the number of defects collected in this list
   *
   * @return size as integer
   */
  public int size()
  {
    check();
    return defects.size();
  }

  /**
   * To avoid NPE check the defect list
   */
  private void check()
  {
    if (defects == null)
    {
      defects = new ArrayList<>();
    }
  }
}
