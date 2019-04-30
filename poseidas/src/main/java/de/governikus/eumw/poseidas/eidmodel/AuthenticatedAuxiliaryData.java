/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidmodel;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;


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
      communityID = communityID.replaceAll(" ", "");
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
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToCounty
                                             + messageIII);
        }
        break;
      case 8:
        if (!communityID.matches(upToDistrict))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToDistrict
                                             + messageIII);
        }
        break;
      case 6:
        if (!communityID.matches(upToState))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToState
                                             + messageIII);
        }
        break;
      case 4:
        if (!communityID.matches(upToCountry))
        {
          throw new IllegalArgumentException(messageI + communityID.length() + messageII + upToCountry
                                             + messageIII);
        }
        break;
      case 0:
        break;
      default:
        String patterns = "  - <" + upToMunicipality + ">\n  - <" + upToDistrict + ">\n  - <" + upToState
                          + ">\n  - <" + upToCountry + ">\n  - < >";
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
   * Try to set a string as community identifier. Null values will be set to empty strings. If string has
   * wrong format exception is thrown
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
   * Encode the object to a asn1 byte[].
   *
   * @return the asn1 structured AuthenticatedAuxiliaryData as byte[]
   */
  public byte[] getEncoded()
  {
    List<ASN1> childs = new ArrayList<>();
    if (ageVerification != null)
    {
      ASN1 iod = new OID(OID_STR_AGE_VERIFICATION);
      ASN1 data = new ASN1(ASN1_ASN1_DISCRETIONARY_DATA_TAG, ageVerification.getBytes(StandardCharsets.UTF_8));
      byte[] bytes = ByteUtil.combine(iod.getEncoded(), data.getEncoded());
      ASN1 dataTemplate = new ASN1(ASN1_DISCRETIONARY_DATA_TEMPLATE_TAG, bytes);
      childs.add(dataTemplate);
    }
    if (documentVerification != null)
    {
      ASN1 iod = new OID(OID_STR_DOCUMENT_VERIFICATION);
      ASN1 data = new ASN1(ASN1_ASN1_DISCRETIONARY_DATA_TAG,
                           documentVerification.getBytes(StandardCharsets.UTF_8));
      byte[] bytes = ByteUtil.combine(iod.getEncoded(), data.getEncoded());
      ASN1 dataTemplate = new ASN1(ASN1_DISCRETIONARY_DATA_TEMPLATE_TAG, bytes);
      childs.add(dataTemplate);
    }
    if (communityVerification != null && !communityVerification.equals(""))
    {
      ASN1 iod = new OID(OID_STR_COMMUNITY_VERIFICATION);
      ASN1 data = new ASN1(ASN1_ASN1_DISCRETIONARY_DATA_TAG, Hex.parse(communityVerification));
      byte[] bytes = ByteUtil.combine(iod.getEncoded(), data.getEncoded());
      ASN1 dataTemplate = new ASN1(ASN1_DISCRETIONARY_DATA_TEMPLATE_TAG, bytes);
      childs.add(dataTemplate);
    }
    if (this.psMessage != null && this.psMessage.length > 0)
    {
      ASN1 oid = new OID(OID_STR_PS_MESSAGE);
      ASN1 data = new ASN1(ASN1_ASN1_DISCRETIONARY_DATA_TAG, this.psMessage);
      byte[] bytes = ByteUtil.combine(oid.getEncoded(), data.getEncoded());
      ASN1 dataTemplate = new ASN1(ASN1_DISCRETIONARY_DATA_TEMPLATE_TAG, bytes);
      childs.add(dataTemplate);
    }
    if (!childs.isEmpty())
    {
      byte[] childBytes = childs.get(0).getEncoded();
      for ( int i = 1 ; i < childs.size() ; i++ )
      {
        childBytes = ByteUtil.combine(childBytes, childs.get(i).getEncoded());
      }
      ASN1 authenticationAsn1 = new ASN1(ASN1_AUTHENTICATION_TAG, childBytes);
      return authenticationAsn1.getEncoded();
    }
    else
    {
      return new byte[]{};
    }
  }
}
