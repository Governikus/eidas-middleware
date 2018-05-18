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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;

import de.governikus.eumw.poseidas.eidserver.model.signeddata.DefectKnown.DefectType;


/**
 * Defect as defined in TR-03129, Appendix A.1.<br />
 * <br />
 * <code>Defect  :: = SEQUENCE{<br /> signerIdentifier  signerIdentifier<br /> certificateHash  OCTECT STRING OPTIONAL<br /> knownDefects  SET OF KnownDefect<br /> }</code>
 * <p>
 * with Signer Identifier is: <br>
 * SignerIdentifier ::= CHOICE{<br />
 * issuerAndSerialNumber IssuerAndSerialNumber,<br />
 * subjectKeyIdentifier [0] SubjectKeyIdentifier<br />
 * }
 *
 * @author Ole Behrens
 */
public class Defect
{

  private static final Log LOGGER = LogFactory.getLog(Defect.class.getName());

  private IssuerAndSerialNumber issuerAndSerialNumber;

  private byte[] subjectKeyIdentifier;

  private byte[] certificateHash;

  private List<DefectKnown> knownDefects;

  Defect(ASN1Sequence sequence) throws IOException
  {
    check();
    int size = sequence.size();
    if (size != 2 && size != 3)
    {
      throw new IOException("ASN1Sequence with unexpected length of elements: " + size);
    }
    for ( int i = 0 ; i < sequence.size() ; i++ )
    {
      ASN1Encodable objectAt = sequence.getObjectAt(i);
      // First element must identify the defect
      if (i == 0)
      {
        // Get the choice for SignerIdentifier element
        if (objectAt instanceof ASN1Sequence)
        {
          LOGGER.debug("SignerIdentifier: IssuerAndSerialNumber");
          // Sequence indicates issuer and serial number is used
          ASN1Sequence issuerAndSerialNumber = (ASN1Sequence)objectAt;
          if (issuerAndSerialNumber.size() < 2)
          {
            throw new IOException("IssuerAndSerialNumber has not enough elements to be build");
          }
          else if (issuerAndSerialNumber.size() > 2)
          {
            LOGGER.debug("IssuerAndSerialNumber with unexpected format ("
                         + issuerAndSerialNumber.size() + ")");
          }
          ASN1Encodable nameSequence = issuerAndSerialNumber.getObjectAt(0);
          X500Name issuerName = null;
          if (nameSequence instanceof ASN1Sequence)
          {
            issuerName = X500Name.getInstance(nameSequence);
          }
          else
          {
            throw new IOException("Cannot extract issuer from " + nameSequence);
          }

          ASN1Encodable serialInteger = issuerAndSerialNumber.getObjectAt(1);
          BigInteger serialNumber = null;
          if (serialInteger instanceof ASN1Integer)
          {
            ASN1Integer serial = (ASN1Integer)serialInteger;
            serialNumber = serial.getValue();
          }
          else
          {
            throw new IOException("Cannot extract serial from " + serialInteger);
          }
          this.issuerAndSerialNumber = new IssuerAndSerialNumber(issuerName, serialNumber);
        }
        else if (objectAt instanceof ASN1OctetString)
        {
          LOGGER.debug("SignerIdentifier: SubjectKeyIdentifier");
          // Octets are subjectKeyIdentifier representation
          ASN1OctetString subjectKeyIdentifier = (ASN1OctetString)objectAt;
          this.subjectKeyIdentifier = subjectKeyIdentifier.getOctets();
        }
        else
        {
          throw new IOException("Cannot SubjectKeyIdentifier from " + objectAt);
        }
      }

      // Optional:
      // If neither issuer and serial nor the subject key id uniquely identify the document signer the hash of
      // the document signer certificate MUST additionally be included
      else if (objectAt instanceof ASN1OctetString)
      {
        LOGGER.debug("Optional information: document signer certficate hash");
        ASN1OctetString certificateHash = (ASN1OctetString)objectAt;
        this.certificateHash = certificateHash.getOctets();
      }

      // Defect contains KnownDefects
      else if (objectAt instanceof ASN1Set)
      {
        LOGGER.debug("Collect set of known defects");
        ASN1Set setOfKnownDefects = (ASN1Set)objectAt;
        int sizeOfKnownDefects = setOfKnownDefects.size();
        for ( int j = 0 ; j < sizeOfKnownDefects ; j++ )
        {
          ASN1Encodable knownDefect = setOfKnownDefects.getObjectAt(j);
          if (knownDefect instanceof ASN1Sequence)
          {
            DefectKnown knownDefectToAdd = new DefectKnown((ASN1Sequence)knownDefect);
            knownDefects.add(knownDefectToAdd);
          }
        }
      }

      // Defect with invalid elements
      else
      {
        throw new IOException("Contains invalid element: " + objectAt);
      }
    }
  }

  /**
   * Indicates if this defect can be identified by issuer and serial number
   *
   * @return true if issuer and serial found
   */
  boolean containsIssuerAndSerialNumber()
  {
    if (issuerAndSerialNumber == null)
    {
      return false;
    }
    else
    {
      return true;
    }
  }

  /**
   * Indicates if this defect contains known defects of specific types
   *
   * @param type to be checked
   * @return true if known defects found for this type
   */
  public boolean containsKnownDefectsOfType(DefectKnown.DefectType type)
  {
    if (getKnownDefectsOfType(type).isEmpty())
    {
      return false;
    }
    else
    {
      return true;
    }
  }

  /**
   * Indicates if this defect can be identified by the subject key identifier
   *
   * @return true if subject key id found
   */
  private boolean containsSubjectKeyIdentifier()
  {
    if (subjectKeyIdentifier == null || subjectKeyIdentifier.length < 1)
    {
      return false;
    }
    else
    {
      return true;
    }
  }

  /**
   * Indicates if this defect contains the optional certificate hash
   *
   * @return true if hash is available
   */
  private boolean containsSignerDocumentCertificateHash()
  {
    if (certificateHash == null || certificateHash.length < 1)
    {
      return false;
    }
    else
    {
      return true;
    }
  }

  /**
   * Avoid NPE for inner known defects
   */
  private void check()
  {
    if (knownDefects == null)
    {
      knownDefects = new ArrayList<>();
    }
  }

  /**
   * Get all known defects for this defect
   *
   * @return list with defects
   */
  public List<DefectKnown> getKnownDefects()
  {
    check();
    return new ArrayList<>(knownDefects);
  }

  public List<DefectKnown> getKnownDefectsOfType(DefectType type)
  {
    check();
    List<DefectKnown> knownDefects = new ArrayList<>();
    for ( DefectKnown knownDefect : this.knownDefects )
    {
      if (knownDefect.isType(type))
      {
        knownDefects.add(knownDefect);
      }
    }
    return knownDefects;
  }

  /**
   * Get the certificate hash for signer document if existing
   *
   * @return byte array for hash or null if not existing
   */
  public byte[] getSignerDocumentCertificateHash()
  {
    if (containsSignerDocumentCertificateHash())
    {
      return certificateHash.clone();
    }
    else
    {
      return null;
    }
  }

  /**
   * Get issuer and serial number
   *
   * @return the DocumentIdentifier or null if not available
   */
  public IssuerAndSerialNumber getSignerDocumentIdentifier()
  {
    if (issuerAndSerialNumber == null)
    {
      return null;
    }
    else
    {
      return issuerAndSerialNumber;
    }
  }

  /**
   * Get the issuer name for signer document
   *
   * @return name or null if no issuer found
   */
  public String getSignerDocumentIssuer()
  {
    return issuerAndSerialNumber.getName().toString();
  }

  /**
   * Get serial number for signer document
   *
   * @return serial or null if no number found
   */
  public int getSignerDocumentSerialNumber()
  {
    if (issuerAndSerialNumber == null)
    {
      return -1;
    }
    {
      return issuerAndSerialNumber.getCertificateSerialNumber().getValue().intValue();
    }
  }

  /**
   * Get the subject key identifier for signer document
   *
   * @return the byte array or null if no identifier found
   */
  public byte[] getSignerDocumentSubjectKeyIdentifier()
  {
    if (containsSubjectKeyIdentifier())
    {
      return subjectKeyIdentifier.clone();
    }
    else
    {
      return null;
    }
  }
}
