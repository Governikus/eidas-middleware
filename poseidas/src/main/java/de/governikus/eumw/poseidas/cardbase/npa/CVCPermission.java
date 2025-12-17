/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.npa;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATConstants;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.AuthenticationTerminals;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.BitIdentifier;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate.ChatTerminalType;
import de.governikus.eumw.poseidas.cardbase.constants.EIDConstants;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;


/**
 * Enumeration of all possible permissions in a CVC. The name matches the {@link EIDKeys} if the option applies to one.
 *
 * @author Alexander Funk
 */
public enum CVCPermission
{

  AUT_READ_DG01(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.DOCUMENT_TYPE.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG1,
                EIDConstants.EID_FID_DG01_DOCUMENT_TYPE,
                EIDConstants.EID_SFID_DG01_DOCUMENT_TYPE),
  AUT_READ_DG02(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.ISSUING_STATE.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG2,
                EIDConstants.EID_FID_DG02_ISSUING_STATE,
                EIDConstants.EID_SFID_DG02_ISSUING_STATE),
  AUT_READ_DG03(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.DATE_OF_EXPIRY.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG3,
                EIDConstants.EID_FID_DG03_DATE_OF_EXPIRY,
                EIDConstants.EID_SFID_DG03_DATE_OF_EXPIRY),
  AUT_READ_DG04(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.GIVEN_NAMES.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG4,
                EIDConstants.EID_FID_DG04_GIVEN_NAMES,
                EIDConstants.EID_SFID_DG04_GIVEN_NAMES),
  AUT_READ_DG05(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.FAMILY_NAMES.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG5,
                EIDConstants.EID_FID_DG05_FAMILY_NAMES,
                EIDConstants.EID_SFID_DG05_FAMILY_NAMES),
  AUT_READ_DG06(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.NOM_DE_PLUME.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG6,
                EIDConstants.EID_FID_DG06_NOM_DE_PLUME,
                EIDConstants.EID_SFID_DG06_NOM_DE_PLUME),
  AUT_READ_DG07(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.ACADEMIC_TITLE.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG7,
                EIDConstants.EID_FID_DG07_ACADEMIC_TITLE,
                EIDConstants.EID_SFID_DG07_ACADEMIC_TITLE),
  AUT_READ_DG08(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.DATE_OF_BIRTH.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG8,
                EIDConstants.EID_FID_DG08_DATE_OF_BIRTH,
                EIDConstants.EID_SFID_DG08_DATE_OF_BIRTH),
  AUT_READ_DG09(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.PLACE_OF_BIRTH.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG9,
                EIDConstants.EID_FID_DG09_PLACE_OF_BIRTH,
                EIDConstants.EID_SFID_DG09_PLACE_OF_BIRTH),
  AUT_READ_DG10(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.NATIONALITY.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG10,
                EIDConstants.EID_FID_DG10_NATIONALITY,
                EIDConstants.EID_SFID_DG10_NATIONALITY),
  AUT_READ_DG11(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.SEX.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG11,
                EIDConstants.EID_FID_DG11_SEX,
                EIDConstants.EID_SFID_DG11_SEX),
  AUT_READ_DG12(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.OPTIONAL_DATA_R.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG12,
                EIDConstants.EID_FID_DG12_OPTIONAL_DATA_R,
                EIDConstants.EID_SFID_DG12_OPTIONAL_DATA_R),
  AUT_READ_DG13(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.BIRTH_NAME.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG13,
                EIDConstants.EID_FID_DG13_BIRTH_NAME,
                EIDConstants.EID_SFID_DG13_BIRTH_NAME),
  AUT_READ_DG14(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.WRITTEN_SIGNATURE.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG14,
                EIDConstants.EID_FID_DG14_WRITTEN_SIGNATURE,
                EIDConstants.EID_SFID_DG14_WRITTEN_SIGNATURE),
  AUT_READ_DG15(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.DATE_OF_ISSUANCE.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG15,
                EIDConstants.EID_FID_DG15_DATE_OF_ISSUANCE,
                EIDConstants.EID_SFID_DG15_DATE_OF_ISSUANCE),
  AUT_READ_DG16(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDConstants.EID_NAME_DG16_RFU04,
                AuthenticationTerminals.AccessRightEnum.READ_DG16,
                EIDConstants.EID_FID_DG16_RFU04,
                EIDConstants.EID_SFID_DG16_RFU04),
  AUT_READ_DG17(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.PLACE_OF_RESIDENCE.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG17,
                EIDConstants.EID_FID_DG17_PLACE_OF_RESIDENCE,
                EIDConstants.EID_SFID_DG17_PLACE_OF_RESIDENCE),
  AUT_READ_DG18(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.MUNICIPALITY_ID.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG18,
                EIDConstants.EID_FID_DG18_MUNICIPALITY_ID,
                EIDConstants.EID_SFID_DG18_MUNICIPALITY_ID),
  AUT_READ_DG19(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.RESIDENCE_PERMIT_I.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG19,
                EIDConstants.EID_FID_DG19_RESIDENCE_PERMIT_I,
                EIDConstants.EID_SFID_DG19_RESIDENCE_PERMIT_I),
  AUT_READ_DG20(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.RESIDENCE_PERMIT_II.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG20,
                EIDConstants.EID_FID_DG20_RESIDENCE_PERMIT_II,
                EIDConstants.EID_SFID_DG20_RESIDENCE_PERMIT_II),
  AUT_READ_DG21(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.PHONE_NUMBER.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG21,
                EIDConstants.EID_FID_DG21_PHONE_NUMBER,
                EIDConstants.EID_SFID_DG21_PHONE_NUMBER),
  AUT_READ_DG22(ChatTerminalType.AUTHENTICATION_TERMINAL,
                EIDKeys.EMAIL_ADDRESS.name(),
                AuthenticationTerminals.AccessRightEnum.READ_DG22,
                EIDConstants.EID_FID_DG22_EMAIL_ADDRESS,
                EIDConstants.EID_SFID_DG22_EMAIL_ADDRESS),
  AUT_WRITE_DG17(ChatTerminalType.AUTHENTICATION_TERMINAL,
                 EIDConstants.EID_NAME_DG17_PLACE_OF_RESIDENCE,
                 AuthenticationTerminals.AccessRightEnum.WRITE_DG17,
                 EIDConstants.EID_FID_DG17_PLACE_OF_RESIDENCE,
                 EIDConstants.EID_SFID_DG17_PLACE_OF_RESIDENCE),
  AUT_WRITE_DG18(ChatTerminalType.AUTHENTICATION_TERMINAL,
                 EIDConstants.EID_NAME_DG18_MUNICIPALITY_ID,
                 AuthenticationTerminals.AccessRightEnum.WRITE_DG18,
                 EIDConstants.EID_FID_DG18_MUNICIPALITY_ID,
                 EIDConstants.EID_SFID_DG18_MUNICIPALITY_ID),
  AUT_WRITE_DG19(ChatTerminalType.AUTHENTICATION_TERMINAL,
                 EIDConstants.EID_NAME_DG19_RESIDENCE_PERMIT_I,
                 AuthenticationTerminals.AccessRightEnum.WRITE_DG19,
                 EIDConstants.EID_FID_DG19_RESIDENCE_PERMIT_I,
                 EIDConstants.EID_SFID_DG19_RESIDENCE_PERMIT_I),
  AUT_WRITE_DG20(ChatTerminalType.AUTHENTICATION_TERMINAL,
                 EIDConstants.EID_NAME_DG20_RESIDENCE_PERMIT_II,
                 AuthenticationTerminals.AccessRightEnum.WRITE_DG20,
                 EIDConstants.EID_FID_DG20_RESIDENCE_PERMIT_II,
                 EIDConstants.EID_SFID_DG20_RESIDENCE_PERMIT_II),
  AUT_WRITE_DG21(ChatTerminalType.AUTHENTICATION_TERMINAL,
                 EIDConstants.EID_NAME_DG21_PHONE_NUMBER,
                 AuthenticationTerminals.AccessRightEnum.WRITE_DG21,
                 EIDConstants.EID_FID_DG21_PHONE_NUMBER,
                 EIDConstants.EID_SFID_DG21_PHONE_NUMBER),
  AUT_WRITE_DG22(ChatTerminalType.AUTHENTICATION_TERMINAL,
                 EIDConstants.EID_NAME_DG22_EMAIL_ADDRESS,
                 AuthenticationTerminals.AccessRightEnum.WRITE_DG22,
                 EIDConstants.EID_FID_DG22_EMAIL_ADDRESS,
                 EIDConstants.EID_SFID_DG22_EMAIL_ADDRESS),
  AUT_AGE_VERIFICATION(ChatTerminalType.AUTHENTICATION_TERMINAL,
                       EIDKeys.AGE_VERIFICATION.name(),
                       AuthenticationTerminals.AccessRightEnum.AGE_VERIFICATION,
                       null,
                       null),
  AUT_MUNICIPALITY_ID_VERIFICATION(ChatTerminalType.AUTHENTICATION_TERMINAL,
                                   EIDKeys.MUNICIPALITY_ID_VERIFICATION.name(),
                                   AuthenticationTerminals.AccessRightEnum.MUNICIPALITY_ID_VERIFICATION,
                                   null,
                                   null),
  AUT_INSTALL_PIN_MANAGEMENT(ChatTerminalType.AUTHENTICATION_TERMINAL,
                             ATConstants.ACCESS_RIGHT_NAME_PIN_MANAGEMENT,
                             AuthenticationTerminals.AccessRightEnum.PIN_MANAGEMENT,
                             null,
                             null),
  AUT_CAN_ALLOWED(ChatTerminalType.AUTHENTICATION_TERMINAL,
                  ATConstants.ACCESS_RIGHT_NAME_CAN_ALLOWED,
                  AuthenticationTerminals.AccessRightEnum.CAN_ALLOWED,
                  null,
                  null),
  AUT_RESTRICTED_IDENTIFICATION(ChatTerminalType.AUTHENTICATION_TERMINAL,
                                EIDKeys.RESTRICTED_ID.name(),
                                AuthenticationTerminals.AccessRightEnum.RESTRICTED_IDENTIFICATION,
                                null,
                                null),
  AUT_PRIVILEGED_TERMINAL(ChatTerminalType.AUTHENTICATION_TERMINAL,
                          ATConstants.ACCESS_RIGHT_NAME_PRIVILEGED_TERMINAL,
                          AuthenticationTerminals.AccessRightEnum.PRIVILEGED_TERMINAL,
                          null,
                          null);

  private ChatTerminalType terminalType = null;

  private String dataFieldName = null;

  private BitIdentifier accessRightEnum = null;

  private String fid = null;

  private String sfid = null;

  private CVCPermission(ChatTerminalType terminalType,
                        String dataFieldName,
                        BitIdentifier accessRightEnum,
                        String fid,
                        String sfid)
  {
    this.dataFieldName = dataFieldName;
    this.terminalType = terminalType;
    this.accessRightEnum = accessRightEnum;
    this.fid = fid;
    this.sfid = sfid;
  }

  /**
   * get a list of all Chat Options possible for the given terminal type.
   *
   * @param terminalType a terminal type.
   * @return a List with all ChatOption possible for the given terminal type
   */
  public static Set<CVCPermission> getOptions(ChatTerminalType terminalType)
  {
    Set<CVCPermission> result = new HashSet<>();
    for ( CVCPermission tmp : values() )
    {
      if (terminalType == tmp.getTerminalType())
      {
        result.add(tmp);
      }
    }
    return result;
  }

  /**
   * Return specific ChatOption for a given eid key
   *
   * @param eidKey is the eid key
   * @return a specific chat option
   */
  public static Set<CVCPermission> getOption(EIDKeys eidKey)
  {
    Set<CVCPermission> result = new HashSet<>();
    for ( CVCPermission tmp : values() )
    {
      if (eidKey.name().equals(tmp.getDataFieldName()))
      {
        result.add(tmp);
      }
    }
    return result;
  }

  /**
   * get a list of all Chat Options possible for the given eid keys.
   *
   * @param eidKeys
   * @return a List with all ChatOption possible for the given eid keys
   */
  public static Set<CVCPermission> getOptions(Collection<EIDKeys> eidKeys)
  {
    Set<CVCPermission> result = new HashSet<>();
    for ( EIDKeys tmpEidKey : eidKeys )
    {
      result.addAll(getOption(tmpEidKey));
    }
    return result;
  }

  /**
   * @return the current terminal type
   */
  public ChatTerminalType getTerminalType()
  {
    return terminalType;
  }

  /**
   * @return the current data field name
   */
  public String getDataFieldName()
  {
    return dataFieldName;
  }

  public String getDescription()
  {
    return accessRightEnum.getName();
  }

  public int getByteIndex()
  {
    return accessRightEnum.getByteIndex();
  }

  public byte getByteMask()
  {
    return accessRightEnum.getByteMask();
  }

  @Override
  public String toString()
  {
    return name() + " : " + getDescription();
  }

  /**
   * @return the fileID of this ChatOption or null if unknown
   */
  public String getFID()
  {
    return this.fid;
  }

  /**
   * @return the short fileID of this ChatOption or null if unknown
   */
  public String getSFID()
  {
    return this.sfid;
  }

  public BitIdentifier getAccessRightEnum()
  {
    return this.accessRightEnum;
  }

}
