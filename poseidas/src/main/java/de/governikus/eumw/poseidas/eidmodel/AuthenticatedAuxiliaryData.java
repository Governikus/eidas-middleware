/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidmodel;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Hex;


/**
 * <p>
 * Class to handle additional Data required by eCard-API EID authentication
 * </p>
 *
 * @author Edgar Thiel
 * @author Alexander Funk
 * @author Ole Behrens
 */

public class AuthenticatedAuxiliaryData
{

  private static final String OID_STR_PS_MESSAGE = "0.4.0.127.0.7.3.1.4.4";

  private static final String OID_STR_COMMUNITY_VERIFICATION = "0.4.0.127.0.7.3.1.4.3";

  private static final String OID_STR_DOCUMENT_VERIFICATION = "0.4.0.127.0.7.3.1.4.2";

  private static final String OID_STR_AGE_VERIFICATION = "0.4.0.127.0.7.3.1.4.1";

  private static final int ASN1_ASN1_DISCRETIONARY_DATA_TAG = 0x53;

  private static final int ASN1_DISCRETIONARY_DATA_TEMPLATE_TAG = 0x73;

  private static final int ASN1_AUTHENTICATION_TAG = 0x67;

  private String ageVerification = null;

  private String documentVerification = null;

  private String communityVerification = null;

  private byte[] psMessage = null;

  /**
   * Parse the community ID for authentication
   *
   * @param communityID to be parsed
   * @throws IllegalArgumentException
   */
  private void parseCommunityID(String communityID)
  {
    // Avoid null-values
    if (communityID == null)
    {
      communityID = "";
    }
    else
    {
      communityID = communityID.replace(" ", "");
    }
    // Prepare error messages for wrong pattern matching
    String messageI = "CommunityID format wrong: With length [";
    String messageII = "] value must match pattern <";
    String messageIII = ">";

    // Land up to Gemeinde
    String upToMunicipality = "0276..0...0...";
    // Land up to Landkreis
    String upToCounty = "0276..0...";
    // Land up to Regierungsbezirk
    String upToDistrict = "0276..0.";
    // Land up to Bundesland
    String upToState = "0276..";
    // Land
    String upToCountry = "0276";
    switch (communityID.length())
    {
      case 14:
        if (!communityID.matches(upToMunicipality))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToMunicipality
                                             + messageIII);
        }
        break;
      case 10:
        if (!communityID.matches(upToCounty))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToCounty + messageIII);
        }
        break;
      case 8:
        if (!communityID.matches(upToDistrict))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToDistrict + messageIII);
        }
        break;
      case 6:
        if (!communityID.matches(upToState))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToState + messageIII);
        }
        break;
      case 4:
        if (!communityID.matches(upToCountry))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToCountry + messageIII);
        }
        break;
      case 0:
        break;
      default:
        String patterns = "  - <" + upToMunicipality + ">\n  - <" + upToDistrict + ">\n  - <" + upToState + ">\n  - <"
                          + upToCountry + ">\n  - < >";
        throw new IllegalArgumentException("CommunityID length not valid: [" + communityID.length()
                                           + "]. Value must match one of this patterns:\n" + patterns);
    }
    communityVerification = communityID;
  }

  /**
   * @param ageVerification Verify born before, as String "YYYYMMDD"
   */
  public void setAgeVerificationAuxiliaryData(String ageVerification)
  {
    this.ageVerification = ageVerification;
  }

  public String getAgeVerificationAuxiliaryData()
  {
    return this.ageVerification;
  }

  /**
   * @param documentVerification Verify expired after, as String "YYYYMMDD"
   */
  public void setDocumentVerificationAuxiliaryData(String documentVerification)
  {
    this.documentVerification = documentVerification;
  }

  public String getDocumentVerificationAuxiliaryData()
  {
    return this.documentVerification;
  }

  public void setPseudonymousSignatureMessage(byte[] psMessage)
  {
    this.psMessage = psMessage;
  }

  /**
   * Try to set a string as community identifier. Null values will be set to empty strings. If string has wrong format
   * exception is thrown
   *
   * @param communityVerification as String "02 76 XX 0X XX 0X XX" <br>
   *          0276 - Deutschland <br>
   *          xx - Bundesland <br>
   *          0X XX - Regierungsbezirk/Landkreis<br>
   *          0X XX - Gemeinde<br>
   * @throws IllegalArgumentException if the community id doesn't match the specification
   */
  public void setCommunityIDAuxiliaryData(String communityVerification)
  {
    parseCommunityID(communityVerification);
  }

  /**
   * Encode the object to an asn1 byte[].
   *
   * @return the asn1 structured AuthenticatedAuxiliaryData as byte[]
   */
  public byte[] getEncoded()
  {
    List<ASN1Primitive> children = new ArrayList<>();

    if (ageVerification != null)
    {
      ASN1EncodableVector ageVector = new ASN1EncodableVector();
      ageVector.add(new ASN1ObjectIdentifier(OID_STR_AGE_VERIFICATION));
      ageVector.add(new DEROctetString(ageVerification.getBytes(StandardCharsets.UTF_8)));
      DERSequence ageSeq = new DERSequence(ageVector);
      children.add(new DERTaggedObject(false, ASN1_ASN1_DISCRETIONARY_DATA_TAG, ageSeq));
    }
    if (documentVerification != null)
    {
      ASN1EncodableVector docVector = new ASN1EncodableVector();
      docVector.add(new ASN1ObjectIdentifier(OID_STR_DOCUMENT_VERIFICATION));
      docVector.add(new DEROctetString(documentVerification.getBytes(StandardCharsets.UTF_8)));
      DERSequence docSeq = new DERSequence(docVector);
      children.add(new DERTaggedObject(false, ASN1_ASN1_DISCRETIONARY_DATA_TAG, docSeq));
    }

    if (communityVerification != null && !communityVerification.isEmpty())
    {
      ASN1EncodableVector commVector = new ASN1EncodableVector();
      commVector.add(new ASN1ObjectIdentifier(OID_STR_COMMUNITY_VERIFICATION));
      commVector.add(new DEROctetString(Hex.decode(communityVerification)));
      DERSequence commSeq = new DERSequence(commVector);
      children.add(new DERTaggedObject(false, ASN1_ASN1_DISCRETIONARY_DATA_TAG, commSeq));
    }

    if (psMessage != null && psMessage.length > 0)
    {
      ASN1EncodableVector psVector = new ASN1EncodableVector();
      psVector.add(new ASN1ObjectIdentifier(OID_STR_PS_MESSAGE));
      psVector.add(new DEROctetString(psMessage));
      DERSequence psSeq = new DERSequence(psVector);
      children.add(new DERTaggedObject(false, ASN1_ASN1_DISCRETIONARY_DATA_TAG, psSeq));
    }

    if (!children.isEmpty())
    {
      ASN1EncodableVector mainVector = new ASN1EncodableVector();
      for ( ASN1Primitive child : children )
      {
        mainVector.add(child);
      }
      DERSequence mainSeq = new DERSequence(mainVector);
      DERTaggedObject authenticationAsn1 = new DERTaggedObject(false, ASN1_AUTHENTICATION_TAG, mainSeq);
      try
      {
        return authenticationAsn1.getEncoded();
      }
      catch (Exception e)
      {
        throw new RuntimeException("Failed to encode AuthenticatedAuxiliaryData", e);
      }
    }
    else
    {
      return new byte[]{};
    }
  }
}
