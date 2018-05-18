/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa;

import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATEidAccessConstants.*;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate.ChatTerminalType;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;


public class ATEidAccess extends BaseAccessRoleAndRights
{

  /**
   * This set contains the permissions which can also be in the CHAT. It is important that this set is always
   * kept up-to-date.
   */
  public static final Collection<CVCPermission> EID_DOUBLES;
  static
  {
    Collection<CVCPermission> temp = new HashSet<>();
    temp.add(CVCPermission.AUT_EID_READ_DG01);
    temp.add(CVCPermission.AUT_EID_READ_DG02);
    temp.add(CVCPermission.AUT_EID_READ_DG03);
    temp.add(CVCPermission.AUT_EID_READ_DG04);
    temp.add(CVCPermission.AUT_EID_READ_DG05);
    temp.add(CVCPermission.AUT_EID_READ_DG06);
    temp.add(CVCPermission.AUT_EID_READ_DG07);
    temp.add(CVCPermission.AUT_EID_READ_DG08);
    temp.add(CVCPermission.AUT_EID_READ_DG09);
    temp.add(CVCPermission.AUT_EID_READ_DG10);
    temp.add(CVCPermission.AUT_EID_READ_DG11);
    temp.add(CVCPermission.AUT_EID_READ_DG12);
    temp.add(CVCPermission.AUT_EID_READ_DG13);
    temp.add(CVCPermission.AUT_EID_READ_DG14);
    temp.add(CVCPermission.AUT_EID_READ_DG15);
    temp.add(CVCPermission.AUT_EID_READ_DG16);
    temp.add(CVCPermission.AUT_EID_READ_DG17);
    temp.add(CVCPermission.AUT_EID_READ_DG18);
    temp.add(CVCPermission.AUT_EID_READ_DG19);
    temp.add(CVCPermission.AUT_EID_READ_DG20);
    temp.add(CVCPermission.AUT_EID_READ_DG21);
    temp.add(CVCPermission.AUT_EID_READ_DG22);
    temp.add(CVCPermission.AUT_EID_WRITE_DG17);
    temp.add(CVCPermission.AUT_EID_WRITE_DG18);
    temp.add(CVCPermission.AUT_EID_WRITE_DG19);
    temp.add(CVCPermission.AUT_EID_WRITE_DG20);
    temp.add(CVCPermission.AUT_EID_WRITE_DG21);
    temp.add(CVCPermission.AUT_EID_WRITE_DG22);
    EID_DOUBLES = Collections.unmodifiableCollection(temp);
  }

  /**
   * This set contains the permissions which can also be in the CHAT. It is important that this set is always
   * kept up-to-date.
   */
  public static final Collection<CVCPermission> CHAT_DOUBLES;
  static
  {
    Collection<CVCPermission> temp = new HashSet<>();
    temp.add(CVCPermission.AUT_READ_DG01);
    temp.add(CVCPermission.AUT_READ_DG02);
    temp.add(CVCPermission.AUT_READ_DG03);
    temp.add(CVCPermission.AUT_READ_DG04);
    temp.add(CVCPermission.AUT_READ_DG05);
    temp.add(CVCPermission.AUT_READ_DG06);
    temp.add(CVCPermission.AUT_READ_DG07);
    temp.add(CVCPermission.AUT_READ_DG08);
    temp.add(CVCPermission.AUT_READ_DG09);
    temp.add(CVCPermission.AUT_READ_DG10);
    temp.add(CVCPermission.AUT_READ_DG11);
    temp.add(CVCPermission.AUT_READ_DG12);
    temp.add(CVCPermission.AUT_READ_DG13);
    temp.add(CVCPermission.AUT_READ_DG14);
    temp.add(CVCPermission.AUT_READ_DG15);
    temp.add(CVCPermission.AUT_READ_DG16);
    temp.add(CVCPermission.AUT_READ_DG17);
    temp.add(CVCPermission.AUT_READ_DG18);
    temp.add(CVCPermission.AUT_READ_DG19);
    temp.add(CVCPermission.AUT_READ_DG20);
    temp.add(CVCPermission.AUT_READ_DG21);
    temp.add(CVCPermission.AUT_READ_DG22);
    temp.add(CVCPermission.AUT_WRITE_DG17);
    temp.add(CVCPermission.AUT_WRITE_DG18);
    temp.add(CVCPermission.AUT_WRITE_DG19);
    temp.add(CVCPermission.AUT_WRITE_DG20);
    temp.add(CVCPermission.AUT_WRITE_DG21);
    temp.add(CVCPermission.AUT_WRITE_DG22);
    CHAT_DOUBLES = Collections.unmodifiableCollection(temp);
  }

  public ATEidAccess(byte[] bytes) throws IOException
  {
    super(bytes, VALUE_BYTE_COUNT, ACCESS_ROLES_LIST, ACCESS_RIGHTS_LIST);
  }

  /**
   * Get an array of all access rights that are allowed by this instance.
   * 
   * @return an array.
   */
  public Set<CVCPermission> getAllRights()
  {
    Set<CVCPermission> options = CVCPermission.getOptions(ChatTerminalType.AUTHENTICATION_TERMINAL);
    Set<CVCPermission> result = new HashSet<>();
    for ( CVCPermission chatOption : options )
    {
      if (existsRight(chatOption.getAccessRightEnum()))
      {
        result.add(chatOption);
      }
    }
    return result;
  }

  public static ATEidAccess constructFromCVCPermissions(Collection<CVCPermission> options,
                                                        Collection<AccessRightEnum> pscAccessRights)
    throws IOException
  {
    byte[] matrixBytes = new byte[VALUE_BYTE_COUNT];
    for ( CVCPermission o : options )
    {
      if (!(o.getAccessRightEnum() instanceof ATEidAccess.AccessRightEnum))
      {
        continue;
      }
      matrixBytes[o.getByteIndex()] |= o.getByteMask();
    }
    if (options.contains(CVCPermission.AUT_SF_PSC))
    {
      for ( AccessRightEnum r : pscAccessRights )
      {
        matrixBytes[r.getByteIndex()] |= r.getByteMask();
      }
    }
    ASN1 asn1 = new ASN1(ASN1EidConstants.TAG_DISCRETIONARY_DATA, matrixBytes);
    return new ATEidAccess(asn1.getEncoded());
  }

  public boolean isReadDocumentType()
  {
    return this.existsRight(AccessRightEnum.READ_DG01);
  }

  public boolean isReadIssuingState()
  {
    return this.existsRight(AccessRightEnum.READ_DG02);
  }

  public boolean isReadDateOfExpiry()
  {
    return this.existsRight(AccessRightEnum.READ_DG03);
  }

  public boolean isReadGivenNames()
  {
    return this.existsRight(AccessRightEnum.READ_DG04);
  }

  public boolean isReadFamilyNames()
  {
    return this.existsRight(AccessRightEnum.READ_DG05);
  }

  public boolean isReadNomDePlume()
  {
    return this.existsRight(AccessRightEnum.READ_DG06);
  }

  public boolean isReadAcademicTitle()
  {
    return this.existsRight(AccessRightEnum.READ_DG07);
  }

  public boolean isReadDateOfBirth()
  {
    return this.existsRight(AccessRightEnum.READ_DG08);
  }

  public boolean isReadPlaceOfBirth()
  {
    return this.existsRight(AccessRightEnum.READ_DG09);
  }

  public boolean isReadNationality()
  {
    return this.existsRight(AccessRightEnum.READ_DG10);
  }

  public boolean isReadSex()
  {
    return this.existsRight(AccessRightEnum.READ_DG11);
  }

  public boolean isReadOptionalDataR()
  {
    return this.existsRight(AccessRightEnum.READ_DG12);
  }

  public boolean isReadBirthName()
  {
    return this.existsRight(AccessRightEnum.READ_DG13);
  }

  public boolean isReadWrittenSignature()
  {
    return this.existsRight(AccessRightEnum.READ_DG14);
  }

  public boolean isReadDateOfIssuance()
  {
    return this.existsRight(AccessRightEnum.READ_DG15);
  }

  public boolean isReadRFU4()
  {
    return this.existsRight(AccessRightEnum.READ_DG16);
  }

  public boolean isReadPlaceOfResidence()
  {
    return this.existsRight(AccessRightEnum.READ_DG17);
  }

  public boolean isReadMunicipalityID()
  {
    return this.existsRight(AccessRightEnum.READ_DG18);
  }

  public boolean isReadResidencePermitI()
  {
    return this.existsRight(AccessRightEnum.READ_DG19);
  }

  public boolean isReadResidencePermitII()
  {
    return this.existsRight(AccessRightEnum.READ_DG20);
  }

  public boolean isReadPhoneNumber()
  {
    return this.existsRight(AccessRightEnum.READ_DG21);
  }

  public boolean isReadEmailAddress()
  {
    return this.existsRight(AccessRightEnum.READ_DG22);
  }

  public boolean isPSCDocumentType()
  {
    return this.existsRight(AccessRightEnum.PSC_DG01);
  }

  public boolean isPSCIssuingState()
  {
    return this.existsRight(AccessRightEnum.PSC_DG02);
  }

  public boolean isPSCDateOfExpiry()
  {
    return this.existsRight(AccessRightEnum.PSC_DG03);
  }

  public boolean isPSCGivenNames()
  {
    return this.existsRight(AccessRightEnum.PSC_DG04);
  }

  public boolean isPSCFamilyNames()
  {
    return this.existsRight(AccessRightEnum.PSC_DG05);
  }

  public boolean isPSCNomDePlume()
  {
    return this.existsRight(AccessRightEnum.PSC_DG06);
  }

  public boolean isPSCAcademicTitle()
  {
    return this.existsRight(AccessRightEnum.PSC_DG07);
  }

  public boolean isPSCDateOfBirth()
  {
    return this.existsRight(AccessRightEnum.PSC_DG08);
  }

  public boolean isPSCPlaceOfBirth()
  {
    return this.existsRight(AccessRightEnum.PSC_DG09);
  }

  public boolean isPSCNationality()
  {
    return this.existsRight(AccessRightEnum.PSC_DG10);
  }

  public boolean isPSCSex()
  {
    return this.existsRight(AccessRightEnum.PSC_DG11);
  }

  public boolean isPSCOptionalDataR()
  {
    return this.existsRight(AccessRightEnum.PSC_DG12);
  }

  public boolean isPSCBirthName()
  {
    return this.existsRight(AccessRightEnum.PSC_DG13);
  }

  public boolean isPSCWrittenSignature()
  {
    return this.existsRight(AccessRightEnum.PSC_DG14);
  }

  public boolean isPSCDateOfIssuance()
  {
    return this.existsRight(AccessRightEnum.PSC_DG15);
  }

  public boolean isPSCRFU4()
  {
    return this.existsRight(AccessRightEnum.PSC_DG16);
  }

  public boolean isPSCPlaceOfResidence()
  {
    return this.existsRight(AccessRightEnum.PSC_DG17);
  }

  public boolean isPSCMunicipalityID()
  {
    return this.existsRight(AccessRightEnum.PSC_DG18);
  }

  public boolean isPSCResidencePermitI()
  {
    return this.existsRight(AccessRightEnum.PSC_DG19);
  }

  public boolean isPSCResidencePermitII()
  {
    return this.existsRight(AccessRightEnum.PSC_DG20);
  }

  public boolean isPSCPhoneNumber()
  {
    return this.existsRight(AccessRightEnum.PSC_DG21);
  }

  public boolean isPSCEmailAddress()
  {
    return this.existsRight(AccessRightEnum.PSC_DG22);
  }

  /**
   * Enum of access rights for Authentication Terminal Special Functions.
   */
  public enum AccessRightEnum implements BitIdentifier
  {
    /**
     * Include DG22 to PSC.
     */
    PSC_DG22(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG22, ACCESS_RIGHT_INDEX_PSC_DG22,
                                   ACCESS_RIGHT_MASK_PSC_DG22)),

    /**
     * Write/Erase DG22.
     */
    WRITE_DG22(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_DG22, ACCESS_RIGHT_INDEX_WRITE_DG22,
                                     ACCESS_RIGHT_MASK_WRITE_DG22)),

    /**
     * Compare DG22.
     */
    COMPARE_DG22(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG22, ACCESS_RIGHT_INDEX_COMPARE_DG22,
                                       ACCESS_RIGHT_MASK_COMPARE_DG22)),

    /**
     * Read DG22.
     */
    READ_DG22(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG22, ACCESS_RIGHT_INDEX_READ_DG22,
                                    ACCESS_RIGHT_MASK_READ_DG22)),

    /**
     * Include DG21 to PSC.
     */
    PSC_DG21(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG21, ACCESS_RIGHT_INDEX_PSC_DG21,
                                   ACCESS_RIGHT_MASK_PSC_DG21)),

    /**
     * Write/Erase DG21.
     */
    WRITE_DG21(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_DG21, ACCESS_RIGHT_INDEX_WRITE_DG21,
                                     ACCESS_RIGHT_MASK_WRITE_DG21)),

    /**
     * Compare DG21.
     */
    COMPARE_DG21(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG21, ACCESS_RIGHT_INDEX_COMPARE_DG21,
                                       ACCESS_RIGHT_MASK_COMPARE_DG21)),

    /**
     * Read DG21.
     */
    READ_DG21(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG21, ACCESS_RIGHT_INDEX_READ_DG21,
                                    ACCESS_RIGHT_MASK_READ_DG21)),

    /**
     * Include DG20 to PSC.
     */
    PSC_DG20(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG20, ACCESS_RIGHT_INDEX_PSC_DG20,
                                   ACCESS_RIGHT_MASK_PSC_DG20)),

    /**
     * Write/Erase DG20.
     */
    WRITE_DG20(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_DG20, ACCESS_RIGHT_INDEX_WRITE_DG20,
                                     ACCESS_RIGHT_MASK_WRITE_DG20)),

    /**
     * Compare DG20.
     */
    COMPARE_DG20(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG20, ACCESS_RIGHT_INDEX_COMPARE_DG20,
                                       ACCESS_RIGHT_MASK_COMPARE_DG20)),

    /**
     * Read DG20.
     */
    READ_DG20(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG20, ACCESS_RIGHT_INDEX_READ_DG20,
                                    ACCESS_RIGHT_MASK_READ_DG20)),

    /**
     * Include DG19 to PSC.
     */
    PSC_DG19(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG19, ACCESS_RIGHT_INDEX_PSC_DG19,
                                   ACCESS_RIGHT_MASK_PSC_DG19)),

    /**
     * Write/Erase DG19.
     */
    WRITE_DG19(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_DG19, ACCESS_RIGHT_INDEX_WRITE_DG19,
                                     ACCESS_RIGHT_MASK_WRITE_DG19)),

    /**
     * Compare DG19.
     */
    COMPARE_DG19(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG19, ACCESS_RIGHT_INDEX_COMPARE_DG19,
                                       ACCESS_RIGHT_MASK_COMPARE_DG19)),

    /**
     * Read DG19.
     */
    READ_DG19(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG19, ACCESS_RIGHT_INDEX_READ_DG19,
                                    ACCESS_RIGHT_MASK_READ_DG19)),

    /**
     * Include DG18 to PSC.
     */
    PSC_DG18(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG18, ACCESS_RIGHT_INDEX_PSC_DG18,
                                   ACCESS_RIGHT_MASK_PSC_DG18)),

    /**
     * Write/Erase DG18.
     */
    WRITE_DG18(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_DG18, ACCESS_RIGHT_INDEX_WRITE_DG18,
                                     ACCESS_RIGHT_MASK_WRITE_DG18)),

    /**
     * Compare DG18.
     */
    COMPARE_DG18(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG18, ACCESS_RIGHT_INDEX_COMPARE_DG18,
                                       ACCESS_RIGHT_MASK_COMPARE_DG18)),

    /**
     * Read DG18.
     */
    READ_DG18(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG18, ACCESS_RIGHT_INDEX_READ_DG18,
                                    ACCESS_RIGHT_MASK_READ_DG18)),

    /**
     * Include DG17 to PSC.
     */
    PSC_DG17(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG17, ACCESS_RIGHT_INDEX_PSC_DG17,
                                   ACCESS_RIGHT_MASK_PSC_DG17)),

    /**
     * Write/Erase DG17.
     */
    WRITE_DG17(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_DG17, ACCESS_RIGHT_INDEX_WRITE_DG17,
                                     ACCESS_RIGHT_MASK_WRITE_DG17)),

    /**
     * Compare DG17.
     */
    COMPARE_DG17(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG17, ACCESS_RIGHT_INDEX_COMPARE_DG17,
                                       ACCESS_RIGHT_MASK_COMPARE_DG17)),

    /**
     * Read DG17.
     */
    READ_DG17(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG17, ACCESS_RIGHT_INDEX_READ_DG17,
                                    ACCESS_RIGHT_MASK_READ_DG17)),

    /**
     * Include DG16 to PSC.
     */
    PSC_DG16(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG16, ACCESS_RIGHT_INDEX_PSC_DG16,
                                   ACCESS_RIGHT_MASK_PSC_DG16)),

    /**
     * Compare DG16.
     */
    COMPARE_DG16(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG16, ACCESS_RIGHT_INDEX_COMPARE_DG16,
                                       ACCESS_RIGHT_MASK_COMPARE_DG16)),

    /**
     * Read DG16.
     */
    READ_DG16(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG16, ACCESS_RIGHT_INDEX_READ_DG16,
                                    ACCESS_RIGHT_MASK_READ_DG16)),

    /**
     * Include DG15 to PSC.
     */
    PSC_DG15(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG15, ACCESS_RIGHT_INDEX_PSC_DG15,
                                   ACCESS_RIGHT_MASK_PSC_DG15)),

    /**
     * Compare DG15.
     */
    COMPARE_DG15(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG15, ACCESS_RIGHT_INDEX_COMPARE_DG15,
                                       ACCESS_RIGHT_MASK_COMPARE_DG15)),

    /**
     * Read DG15.
     */
    READ_DG15(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG15, ACCESS_RIGHT_INDEX_READ_DG15,
                                    ACCESS_RIGHT_MASK_READ_DG15)),

    /**
     * Include DG14 to PSC.
     */
    PSC_DG14(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG14, ACCESS_RIGHT_INDEX_PSC_DG14,
                                   ACCESS_RIGHT_MASK_PSC_DG14)),

    /**
     * Compare DG14.
     */
    COMPARE_DG14(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG14, ACCESS_RIGHT_INDEX_COMPARE_DG14,
                                       ACCESS_RIGHT_MASK_COMPARE_DG14)),

    /**
     * Read DG14.
     */
    READ_DG14(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG14, ACCESS_RIGHT_INDEX_READ_DG14,
                                    ACCESS_RIGHT_MASK_READ_DG14)),

    /**
     * Include DG13 to PSC.
     */
    PSC_DG13(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG13, ACCESS_RIGHT_INDEX_PSC_DG13,
                                   ACCESS_RIGHT_MASK_PSC_DG13)),

    /**
     * Compare DG13.
     */
    COMPARE_DG13(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG13, ACCESS_RIGHT_INDEX_COMPARE_DG13,
                                       ACCESS_RIGHT_MASK_COMPARE_DG13)),

    /**
     * Read DG13.
     */
    READ_DG13(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG13, ACCESS_RIGHT_INDEX_READ_DG13,
                                    ACCESS_RIGHT_MASK_READ_DG13)),

    /**
     * Include DG12 to PSC.
     */
    PSC_DG12(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG12, ACCESS_RIGHT_INDEX_PSC_DG12,
                                   ACCESS_RIGHT_MASK_PSC_DG12)),

    /**
     * Compare DG12.
     */
    COMPARE_DG12(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG12, ACCESS_RIGHT_INDEX_COMPARE_DG12,
                                       ACCESS_RIGHT_MASK_COMPARE_DG12)),

    /**
     * Read DG12.
     */
    READ_DG12(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG12, ACCESS_RIGHT_INDEX_READ_DG12,
                                    ACCESS_RIGHT_MASK_READ_DG12)),

    /**
     * Include DG11 to PSC.
     */
    PSC_DG11(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG11, ACCESS_RIGHT_INDEX_PSC_DG11,
                                   ACCESS_RIGHT_MASK_PSC_DG11)),

    /**
     * Compare DG11.
     */
    COMPARE_DG11(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG11, ACCESS_RIGHT_INDEX_COMPARE_DG11,
                                       ACCESS_RIGHT_MASK_COMPARE_DG11)),

    /**
     * Read DG11.
     */
    READ_DG11(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG11, ACCESS_RIGHT_INDEX_READ_DG11,
                                    ACCESS_RIGHT_MASK_READ_DG11)),

    /**
     * Include DG10 to PSC.
     */
    PSC_DG10(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG10, ACCESS_RIGHT_INDEX_PSC_DG10,
                                   ACCESS_RIGHT_MASK_PSC_DG10)),

    /**
     * Compare DG10.
     */
    COMPARE_DG10(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG10, ACCESS_RIGHT_INDEX_COMPARE_DG10,
                                       ACCESS_RIGHT_MASK_COMPARE_DG10)),

    /**
     * Read DG10.
     */
    READ_DG10(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG10, ACCESS_RIGHT_INDEX_READ_DG10,
                                    ACCESS_RIGHT_MASK_READ_DG10)),

    /**
     * Include DG09 to PSC.
     */
    PSC_DG09(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG09, ACCESS_RIGHT_INDEX_PSC_DG09,
                                   ACCESS_RIGHT_MASK_PSC_DG09)),

    /**
     * Compare DG09.
     */
    COMPARE_DG09(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG09, ACCESS_RIGHT_INDEX_COMPARE_DG09,
                                       ACCESS_RIGHT_MASK_COMPARE_DG09)),

    /**
     * Read DG09.
     */
    READ_DG09(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG09, ACCESS_RIGHT_INDEX_READ_DG09,
                                    ACCESS_RIGHT_MASK_READ_DG09)),

    /**
     * Include DG08 to PSC.
     */
    PSC_DG08(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG08, ACCESS_RIGHT_INDEX_PSC_DG08,
                                   ACCESS_RIGHT_MASK_PSC_DG08)),

    /**
     * Compare DG08.
     */
    COMPARE_DG08(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG08, ACCESS_RIGHT_INDEX_COMPARE_DG08,
                                       ACCESS_RIGHT_MASK_COMPARE_DG08)),

    /**
     * Read DG08.
     */
    READ_DG08(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG08, ACCESS_RIGHT_INDEX_READ_DG08,
                                    ACCESS_RIGHT_MASK_READ_DG08)),

    /**
     * Include DG07 to PSC.
     */
    PSC_DG07(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG07, ACCESS_RIGHT_INDEX_PSC_DG07,
                                   ACCESS_RIGHT_MASK_PSC_DG07)),

    /**
     * Compare DG07.
     */
    COMPARE_DG07(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG07, ACCESS_RIGHT_INDEX_COMPARE_DG07,
                                       ACCESS_RIGHT_MASK_COMPARE_DG07)),

    /**
     * Read DG07.
     */
    READ_DG07(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG07, ACCESS_RIGHT_INDEX_READ_DG07,
                                    ACCESS_RIGHT_MASK_READ_DG07)),

    /**
     * Include DG06 to PSC.
     */
    PSC_DG06(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG06, ACCESS_RIGHT_INDEX_PSC_DG06,
                                   ACCESS_RIGHT_MASK_PSC_DG06)),

    /**
     * Compare DG06.
     */
    COMPARE_DG06(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG06, ACCESS_RIGHT_INDEX_COMPARE_DG06,
                                       ACCESS_RIGHT_MASK_COMPARE_DG06)),

    /**
     * Read DG06.
     */
    READ_DG06(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG06, ACCESS_RIGHT_INDEX_READ_DG06,
                                    ACCESS_RIGHT_MASK_READ_DG06)),

    /**
     * Include DG05 to PSC.
     */
    PSC_DG05(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG05, ACCESS_RIGHT_INDEX_PSC_DG05,
                                   ACCESS_RIGHT_MASK_PSC_DG05)),

    /**
     * Compare DG05.
     */
    COMPARE_DG05(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG05, ACCESS_RIGHT_INDEX_COMPARE_DG05,
                                       ACCESS_RIGHT_MASK_COMPARE_DG05)),

    /**
     * Read DG05.
     */
    READ_DG05(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG05, ACCESS_RIGHT_INDEX_READ_DG05,
                                    ACCESS_RIGHT_MASK_READ_DG05)),

    /**
     * Include DG04 to PSC.
     */
    PSC_DG04(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG04, ACCESS_RIGHT_INDEX_PSC_DG04,
                                   ACCESS_RIGHT_MASK_PSC_DG04)),

    /**
     * Compare DG04.
     */
    COMPARE_DG04(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG04, ACCESS_RIGHT_INDEX_COMPARE_DG04,
                                       ACCESS_RIGHT_MASK_COMPARE_DG04)),

    /**
     * Read DG04.
     */
    READ_DG04(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG04, ACCESS_RIGHT_INDEX_READ_DG04,
                                    ACCESS_RIGHT_MASK_READ_DG04)),

    /**
     * Include DG03 to PSC.
     */
    PSC_DG03(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG03, ACCESS_RIGHT_INDEX_PSC_DG03,
                                   ACCESS_RIGHT_MASK_PSC_DG03)),

    /**
     * Compare DG03.
     */
    COMPARE_DG03(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG03, ACCESS_RIGHT_INDEX_COMPARE_DG03,
                                       ACCESS_RIGHT_MASK_COMPARE_DG03)),

    /**
     * Read DG03.
     */
    READ_DG03(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG03, ACCESS_RIGHT_INDEX_READ_DG03,
                                    ACCESS_RIGHT_MASK_READ_DG03)),

    /**
     * Include DG02 to PSC.
     */
    PSC_DG02(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG02, ACCESS_RIGHT_INDEX_PSC_DG02,
                                   ACCESS_RIGHT_MASK_PSC_DG02)),

    /**
     * Compare DG02.
     */
    COMPARE_DG02(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG02, ACCESS_RIGHT_INDEX_COMPARE_DG02,
                                       ACCESS_RIGHT_MASK_COMPARE_DG02)),

    /**
     * Read DG02.
     */
    READ_DG02(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG02, ACCESS_RIGHT_INDEX_READ_DG02,
                                    ACCESS_RIGHT_MASK_READ_DG02)),

    /**
     * Include DG01 to PSC.
     */
    PSC_DG01(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC_DG01, ACCESS_RIGHT_INDEX_PSC_DG01,
                                   ACCESS_RIGHT_MASK_PSC_DG01)),

    /**
     * Compare DG01.
     */
    COMPARE_DG01(new BitIdentifierImpl(ACCESS_RIGHT_NAME_COMPARE_DG01, ACCESS_RIGHT_INDEX_COMPARE_DG01,
                                       ACCESS_RIGHT_MASK_COMPARE_DG01)),

    /**
     * Read DG01.
     */
    READ_DG01(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_DG01, ACCESS_RIGHT_INDEX_READ_DG01,
                                    ACCESS_RIGHT_MASK_READ_DG01)), ;

    // identifier
    private BitIdentifier bitIdentifier = null;

    /**
     * Constructor with identifier.
     * 
     * @param bitIdentifier identifier, <code>null</code> not permitted
     * @throws IllegalArgumentException if identifier <code>null</code>
     */
    private AccessRightEnum(BitIdentifier bitIdentifier)
    {
      if (bitIdentifier == null)
      {
        throw new IllegalArgumentException("BitIdentifier expected");
      }
      this.bitIdentifier = bitIdentifier;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean accept(ASN1 asn1)
    {
      return bitIdentifier.accept(asn1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean accept(byte[] asn1ValueBytes)
    {
      return bitIdentifier.accept(asn1ValueBytes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte getBitMask()
    {
      return bitIdentifier.getBitMask();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getByteIndex()
    {
      return bitIdentifier.getByteIndex();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName()
    {
      return bitIdentifier.getName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte getByteMask()
    {
      return bitIdentifier.getByteMask();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
      return this.getName();
    }
  }
}
