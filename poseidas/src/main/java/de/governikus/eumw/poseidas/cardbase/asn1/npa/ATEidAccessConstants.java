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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATEidAccess.AccessRightEnum;
import de.governikus.eumw.poseidas.cardbase.constants.EIDConstants;


public final class ATEidAccessConstants
{

  /**
   * Suffix of OID for Authentication Terminal extension eID Access: <code>.1</code>.
   */
  private static final String OID_SUFFIX_EID_ACCESS = ".1";

  /**
   * Base OID of access rights for Authentication Terminal extension eID Access:
   * <code>0.4.0.127.0.7.3.1.2.2.1</code>.
   */
  public static final String OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_EID_ACCESS = ATConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL
                                                                                             + OID_SUFFIX_EID_ACCESS;

  /**
   * Count of ASN.1 value bytes: <code>9</code>.
   */
  static final int VALUE_BYTE_COUNT = 9;

  /**
   * Byte index for Include DG22 (eID) to PSC: <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG22 = 0;

  /**
   * Mask for Include DG22 (eID) to PSC: <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG22 = (byte)0x80;

  /**
   * Name for Include DG22 (eID) to PSC: <code>Include DG22 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG22 = "Include DG22 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG22_EMAIL_ADDRESS;

  /**
   * Byte index for Write/Erase DG22 (eID): <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_WRITE_DG22 = 0;

  /**
   * Mask for Write/Erase DG22 (eID): <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_WRITE_DG22 = (byte)0x40;

  /**
   * Name for Write/Erase DG22 (eID): <code>Write/Erase DG22 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_WRITE_DG22 = "Write/Erase DG22 (eID): "
                                                            + EIDConstants.EID_NAME_DG22_EMAIL_ADDRESS;

  /**
   * Byte index for Compare DG22 (eID): <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG22 = 0;

  /**
   * Mask for Compare DG22 (eID): <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG22 = (byte)0x20;

  /**
   * Name for Compare DG22 (eID): <code>Compare DG22 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG22 = "Compare DG22 (eID): "
                                                              + EIDConstants.EID_NAME_DG22_EMAIL_ADDRESS;

  /**
   * Byte index for Read DG22 (eID): <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_READ_DG22 = 0;

  /**
   * Mask for Read DG22 (eID): <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG22 = (byte)0x10;

  /**
   * Name for Read DG22 (eID): <code>Read DG22 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG22 = "Read DG22 (eID): "
                                                           + EIDConstants.EID_NAME_DG22_EMAIL_ADDRESS;

  /**
   * Byte index for Include DG21 (eID) to PSC: <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG21 = 0;

  /**
   * Mask for Include DG21 (eID) to PSC: <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG21 = (byte)0x08;

  /**
   * Name for Include DG21 (eID) to PSC: <code>Include DG21 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG21 = "Include DG21 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG21_PHONE_NUMBER;

  /**
   * Byte index for Write/Erase DG21 (eID): <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_WRITE_DG21 = 0;

  /**
   * Mask for Write/Erase DG21 (eID): <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_WRITE_DG21 = (byte)0x04;

  /**
   * Name for Write/Erase DG21 (eID): <code>Write/Erase DG21 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_WRITE_DG21 = "Write/Erase DG21 (eID): "
                                                            + EIDConstants.EID_NAME_DG21_PHONE_NUMBER;

  /**
   * Byte index for Compare DG21 (eID): <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG21 = 0;

  /**
   * Mask for Compare DG21 (eID): <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG21 = (byte)0x02;

  /**
   * Name for Compare DG21 (eID): <code>Compare DG21 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG21 = "Compare DG21 (eID): "
                                                              + EIDConstants.EID_NAME_DG21_PHONE_NUMBER;

  /**
   * Byte index for Read DG21 (eID): <code>0</code>.
   */
  static final int ACCESS_RIGHT_INDEX_READ_DG21 = 0;

  /**
   * Mask for Read DG21 (eID): <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG21 = (byte)0x01;

  /**
   * Name for Read DG21 (eID): <code>Read DG21 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG21 = "Read DG21 (eID): "
                                                           + EIDConstants.EID_NAME_DG21_PHONE_NUMBER;

  /**
   * Byte index for Include DG20 (eID) to PSC: <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG20 = 1;

  /**
   * Mask for Include DG20 (eID) to PSC: <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG20 = (byte)0x80;

  /**
   * Name for Include DG20 (eID) to PSC: <code>Include DG20 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG20 = "Include DG20 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG20_RESIDENCE_PERMIT_II;

  /**
   * Byte index for Write/Erase DG20 (eID): <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_WRITE_DG20 = 1;

  /**
   * Mask for Write/Erase DG20 (eID): <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_WRITE_DG20 = (byte)0x40;

  /**
   * Name for Write/Erase DG20 (eID): <code>Write/Erase DG20 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_WRITE_DG20 = "Write/Erase DG20 (eID): "
                                                            + EIDConstants.EID_NAME_DG20_RESIDENCE_PERMIT_II;

  /**
   * Byte index for Compare DG20 (eID): <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG20 = 1;

  /**
   * Mask for Compare DG20 (eID): <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG20 = (byte)0x20;

  /**
   * Name for Compare DG20 (eID): <code>Compare DG20 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG20 = "Compare DG20 (eID): "
                                                              + EIDConstants.EID_NAME_DG20_RESIDENCE_PERMIT_II;

  /**
   * Byte index for Read DG20 (eID): <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_READ_DG20 = 1;

  /**
   * Mask for Read DG20 (eID): <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG20 = (byte)0x10;

  /**
   * Name for Read DG20 (eID): <code>Read DG20 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG20 = "Read DG20 (eID): "
                                                           + EIDConstants.EID_NAME_DG20_RESIDENCE_PERMIT_II;

  /**
   * Byte index for Include DG19 (eID) to PSC: <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG19 = 1;

  /**
   * Mask for Include DG19 (eID) to PSC: <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG19 = (byte)0x08;

  /**
   * Name for Include DG19 (eID) to PSC: <code>Include DG19 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG19 = "Include DG19 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG19_RESIDENCE_PERMIT_I;

  /**
   * Byte index for Write/Erase DG19 (eID): <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_WRITE_DG19 = 1;

  /**
   * Mask for Write/Erase DG19 (eID): <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_WRITE_DG19 = (byte)0x04;

  /**
   * Name for Write/Erase DG19 (eID): <code>Write/Erase DG19 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_WRITE_DG19 = "Write/Erase DG19 (eID): "
                                                            + EIDConstants.EID_NAME_DG19_RESIDENCE_PERMIT_I;

  /**
   * Byte index for Compare DG19 (eID): <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG19 = 1;

  /**
   * Mask for Compare DG19 (eID): <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG19 = (byte)0x02;

  /**
   * Name for Compare DG19 (eID): <code>Compare DG19 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG19 = "Compare DG19 (eID): "
                                                              + EIDConstants.EID_NAME_DG19_RESIDENCE_PERMIT_I;

  /**
   * Byte index for Read DG19 (eID): <code>1</code>.
   */
  static final int ACCESS_RIGHT_INDEX_READ_DG19 = 1;

  /**
   * Mask for Read DG19 (eID): <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG19 = (byte)0x01;

  /**
   * Name for Read DG19 (eID): <code>Read DG19 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG19 = "Read DG19 (eID): "
                                                           + EIDConstants.EID_NAME_DG19_RESIDENCE_PERMIT_I;

  /**
   * Byte index for Include DG18 (eID) to PSC: <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG18 = 2;

  /**
   * Mask for Include DG18 (eID) to PSC: <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG18 = (byte)0x80;

  /**
   * Name for Include DG18 (eID) to PSC: <code>Include DG18 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG18 = "Include DG18 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG18_MUNICIPALITY_ID;

  /**
   * Byte index for Write/Erase DG18 (eID): <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_WRITE_DG18 = 2;

  /**
   * Mask for Write/Erase DG18 (eID): <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_WRITE_DG18 = (byte)0x40;

  /**
   * Name for Write/Erase DG18 (eID): <code>Write/Erase DG18 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_WRITE_DG18 = "Write/Erase DG18 (eID): "
                                                            + EIDConstants.EID_NAME_DG18_MUNICIPALITY_ID;

  /**
   * Byte index for Compare DG18 (eID): <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG18 = 2;

  /**
   * Mask for Compare DG18 (eID): <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG18 = (byte)0x20;

  /**
   * Name for Compare DG18 (eID): <code>Compare DG18 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG18 = "Compare DG18 (eID): "
                                                              + EIDConstants.EID_NAME_DG18_MUNICIPALITY_ID;

  /**
   * Byte index for Read DG18 (eID): <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_READ_DG18 = 2;

  /**
   * Mask for Read DG18 (eID): <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG18 = (byte)0x10;

  /**
   * Name for Read DG18 (eID): <code>Read DG18 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG18 = "Read DG18 (eID): "
                                                           + EIDConstants.EID_NAME_DG18_MUNICIPALITY_ID;

  /**
   * Byte index for Include DG17 (eID) to PSC: <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG17 = 2;

  /**
   * Mask for Include DG17 (eID) to PSC: <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG17 = (byte)0x08;

  /**
   * Name for Include DG17 (eID) to PSC: <code>Include DG17 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG17 = "Include DG17 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG17_PLACE_OF_RESIDENCE;

  /**
   * Byte index for Write/Erase DG17 (eID): <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_WRITE_DG17 = 2;

  /**
   * Mask for Write/Erase DG17 (eID): <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_WRITE_DG17 = (byte)0x04;

  /**
   * Name for Write/Erase DG17 (eID): <code>Write/Erase DG17 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_WRITE_DG17 = "Write/Erase DG17 (eID): "
                                                            + EIDConstants.EID_NAME_DG17_PLACE_OF_RESIDENCE;

  /**
   * Byte index for Compare DG17 (eID): <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG17 = 2;

  /**
   * Mask for Compare DG17 (eID): <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG17 = (byte)0x02;

  /**
   * Name for Compare DG17 (eID): <code>Compare DG17 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG17 = "Compare DG17 (eID): "
                                                              + EIDConstants.EID_NAME_DG17_PLACE_OF_RESIDENCE;

  /**
   * Byte index for Read DG17 (eID): <code>2</code>.
   */
  static final int ACCESS_RIGHT_INDEX_READ_DG17 = 2;

  /**
   * Mask for Read DG17 (eID): <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG17 = (byte)0x01;

  /**
   * Name for Read DG17 (eID): <code>Read DG17 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG17 = "Read DG17 (eID): "
                                                           + EIDConstants.EID_NAME_DG17_PLACE_OF_RESIDENCE;

  /**
   * Byte index for Include DG16 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG16 = 3;

  /**
   * Mask for Include DG16 (eID) to PSC: <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG16 = (byte)0x80;

  /**
   * Name for Include DG16 (eID) to PSC: <code>Include DG16 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG16 = "Include DG16 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG16_RFU04;

  /**
   * Byte index for Include DG15 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG15 = 3;

  /**
   * Mask for Include DG15 (eID) to PSC: <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG15 = (byte)0x40;

  /**
   * Name for Include DG15 (eID) to PSC: <code>Include DG15 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG15 = "Include DG15 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG15_DATE_OF_ISSUANCE;

  /**
   * Byte index for Include DG14 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG14 = 3;

  /**
   * Mask for Include DG14 (eID) to PSC: <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG14 = (byte)0x20;

  /**
   * Name for Include DG14 (eID) to PSC: <code>Include DG14 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG14 = "Include DG14 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG14_WRITTEN_SIGNATURE;

  /**
   * Byte index for Include DG13 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG13 = 3;

  /**
   * Mask for Include DG13 (eID) to PSC: <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG13 = (byte)0x10;

  /**
   * Name for Include DG13 (eID) to PSC: <code>Include DG13 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG13 = "Include DG13 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG13_BIRTH_NAME;

  /**
   * Byte index for Include DG12 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG12 = 3;

  /**
   * Mask for Include DG12 (eID) to PSC: <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG12 = (byte)0x08;

  /**
   * Name for Include DG12 (eID) to PSC: <code>Include DG12 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG12 = "Include DG12 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG12_OPTIONAL_DATA_R;

  /**
   * Byte index for Include DG11 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG11 = 3;

  /**
   * Mask for Include DG11 (eID) to PSC: <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG11 = (byte)0x04;

  /**
   * Name for Include DG11 (eID) to PSC: <code>Include DG11 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG11 = "Include DG11 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG11_SEX;

  /**
   * Byte index for Include DG10 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG10 = 3;

  /**
   * Mask for Include DG10 (eID) to PSC: <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG10 = (byte)0x02;

  /**
   * Name for Include DG10 (eID) to PSC: <code>Include DG10 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG10 = "Include DG10 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG10_NATIONALITY;

  /**
   * Byte index for Include DG09 (eID) to PSC: <code>3</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG09 = 3;

  /**
   * Mask for Include DG09 (eID) to PSC: <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG09 = (byte)0x01;

  /**
   * Name for Include DG09 (eID) to PSC: <code>Include DG09 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG09 = "Include DG09 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG09_PLACE_OF_BIRTH;

  /**
   * Byte index for Include DG08 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG08 = 4;

  /**
   * Mask for Include DG08 (eID) to PSC: <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG08 = (byte)0x80;

  /**
   * Name for Include DG08 (eID) to PSC: <code>Include DG08 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG08 = "Include DG08 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG08_DATE_OF_BIRTH;

  /**
   * Byte index for Include DG07 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG07 = 4;

  /**
   * Mask for Include DG07 (eID) to PSC: <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG07 = (byte)0x40;

  /**
   * Name for Include DG07 (eID) to PSC: <code>Include DG07 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG07 = "Include DG07 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG07_ACADEMIC_TITLE;

  /**
   * Byte index for Include DG06 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG06 = 4;

  /**
   * Mask for Include DG06 (eID) to PSC: <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG06 = (byte)0x20;

  /**
   * Name for Include DG06 (eID) to PSC: <code>Include DG06 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG06 = "Include DG06 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG06_NOM_DE_PLUME;

  /**
   * Byte index for Include DG05 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG05 = 4;

  /**
   * Mask for Include DG05 (eID) to PSC: <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG05 = (byte)0x10;

  /**
   * Name for Include DG05 (eID) to PSC: <code>Include DG05 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG05 = "Include DG05 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG05_FAMILY_NAMES;

  /**
   * Byte index for Include DG04 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG04 = 4;

  /**
   * Mask for Include DG04 (eID) to PSC: <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG04 = (byte)0x08;

  /**
   * Name for Include DG04 (eID) to PSC: <code>Include DG04 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG04 = "Include DG04 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG04_GIVEN_NAMES;

  /**
   * Byte index for Include DG03 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG03 = 4;

  /**
   * Mask for Include DG03 (eID) to PSC: <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG03 = (byte)0x04;

  /**
   * Name for Include DG03 (eID) to PSC: <code>Include DG03 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG03 = "Include DG03 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG03_DATE_OF_EXPIRY;

  /**
   * Byte index for Include DG02 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG02 = 4;

  /**
   * Mask for Include DG02 (eID) to PSC: <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG02 = (byte)0x02;

  /**
   * Name for Include DG02 (eID) to PSC: <code>Include DG02 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG02 = "Include DG02 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG02_ISSUING_STATE;

  /**
   * Byte index for Include DG01 (eID) to PSC: <code>4</code>.
   */
  static final int ACCESS_RIGHT_INDEX_PSC_DG01 = 4;

  /**
   * Mask for Include DG01 (eID) to PSC: <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_PSC_DG01 = (byte)0x01;

  /**
   * Name for Include DG01 (eID) to PSC: <code>Include DG01 (eID) to PSC</code>.
   */
  static final String ACCESS_RIGHT_NAME_PSC_DG01 = "Include DG01 (eID) to PSC: "
                                                          + EIDConstants.EID_NAME_DG01_DOCUMENT_TYPE;

  /**
   * Byte index for Compare DG16 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG16 = 5;

  /**
   * Mask for Compare DG16 (eID): <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG16 = (byte)0x80;

  /**
   * Name for Compare DG16 (eID): <code>Compare DG16 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG16 = "Compare DG16 (eID): "
                                                              + EIDConstants.EID_NAME_DG16_RFU04;

  /**
   * Byte index for Compare DG15 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG15 = 5;

  /**
   * Mask for Compare DG15 (eID): <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG15 = (byte)0x40;

  /**
   * Name for Compare DG15 (eID): <code>Compare DG15 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG15 = "Compare DG15 (eID): "
                                                              + EIDConstants.EID_NAME_DG15_DATE_OF_ISSUANCE;

  /**
   * Byte index for Compare DG14 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG14 = 5;

  /**
   * Mask for Compare DG14 (eID): <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG14 = (byte)0x20;

  /**
   * Name for Compare DG14 (eID): <code>Compare DG14 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG14 = "Compare DG14 (eID): "
                                                              + EIDConstants.EID_NAME_DG14_WRITTEN_SIGNATURE;

  /**
   * Byte index for Compare DG13 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG13 = 5;

  /**
   * Mask for Compare DG13 (eID): <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG13 = (byte)0x10;

  /**
   * Name for Compare DG13 (eID): <code>Compare DG13 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG13 = "Compare DG13 (eID): "
                                                              + EIDConstants.EID_NAME_DG13_BIRTH_NAME;

  /**
   * Byte index for Compare DG12 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG12 = 5;

  /**
   * Mask for Compare DG12 (eID): <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG12 = (byte)0x08;

  /**
   * Name for Compare DG12 (eID): <code>Compare DG12 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG12 = "Compare DG12 (eID): "
                                                              + EIDConstants.EID_NAME_DG12_OPTIONAL_DATA_R;

  /**
   * Byte index for Compare DG11 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG11 = 5;

  /**
   * Mask for Compare DG11 (eID): <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG11 = (byte)0x04;

  /**
   * Name for Compare DG11 (eID): <code>Compare DG11 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_COMPARE_DG11 = "Compare DG11 (eID): "
                                                              + EIDConstants.EID_NAME_DG11_SEX;

  /**
   * Byte index for Compare DG10 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG10 = 5;

  /**
   * Mask for Compare DG10 (eID): <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG10 = (byte)0x02;

  /**
   * Name for Compare DG10 (eID): <code>Compare DG10 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG10 = "Compare DG10 (eID): "
                                                              + EIDConstants.EID_NAME_DG10_NATIONALITY;

  /**
   * Byte index for Compare DG09 (eID): <code>5</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG09 = 5;

  /**
   * Mask for Compare DG09 (eID): <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG09 = (byte)0x01;

  /**
   * Name for Compare DG09 (eID): <code>Compare DG09 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG09 = "Compare DG09 (eID): "
                                                              + EIDConstants.EID_NAME_DG09_PLACE_OF_BIRTH;

  /**
   * Byte index for Compare DG08 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG08 = 6;

  /**
   * Mask for Compare DG08 (eID): <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG08 = (byte)0x80;

  /**
   * Name for Compare DG08 (eID): <code>Compare DG08 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG08 = "Compare DG08 (eID): "
                                                              + EIDConstants.EID_NAME_DG08_DATE_OF_BIRTH;

  /**
   * Byte index for Compare DG07 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG07 = 6;

  /**
   * Mask for Compare DG07 (eID): <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG07 = (byte)0x40;

  /**
   * Name for Compare DG07 (eID): <code>Compare DG07 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG07 = "Compare DG07 (eID): "
                                                              + EIDConstants.EID_NAME_DG07_ACADEMIC_TITLE;

  /**
   * Byte index for Compare DG06 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG06 = 6;

  /**
   * Mask for Compare DG06 (eID): <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG06 = (byte)0x20;

  /**
   * Name for Compare DG06 (eID): <code>Compare DG06 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG06 = "Compare DG06 (eID): "
                                                              + EIDConstants.EID_NAME_DG06_NOM_DE_PLUME;

  /**
   * Byte index for Compare DG05 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG05 = 6;

  /**
   * Mask for Compare DG05 (eID): <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG05 = (byte)0x10;

  /**
   * Name for Compare DG05 (eID): <code>Compare DG05 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG05 = "Compare DG05 (eID): "
                                                              + EIDConstants.EID_NAME_DG05_FAMILY_NAMES;

  /**
   * Byte index for Compare DG04 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG04 = 6;

  /**
   * Mask for Compare DG04 (eID): <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG04 = (byte)0x08;

  /**
   * Name for Compare DG04 (eID): <code>Compare DG04 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG04 = "Compare DG04 (eID): "
                                                              + EIDConstants.EID_NAME_DG04_GIVEN_NAMES;

  /**
   * Byte index for Compare DG03 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG03 = 6;

  /**
   * Mask for Compare DG03 (eID): <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG03 = (byte)0x04;

  /**
   * Name for Compare DG03 (eID): <code>Compare DG03 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG03 = "Compare DG03 (eID): "
                                                              + EIDConstants.EID_NAME_DG03_DATE_OF_EXPIRY;

  /**
   * Byte index for Compare DG02 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG02 = 6;

  /**
   * Mask for Compare DG02 (eID): <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG02 = (byte)0x02;

  /**
   * Name for Compare DG02 (eID): <code>Compare DG02 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG02 = "Compare DG02 (eID): "
                                                              + EIDConstants.EID_NAME_DG02_ISSUING_STATE;

  /**
   * Byte index for Compare DG01 (eID): <code>6</code>.
   */
  static final int ACCESS_RIGHT_INDEX_COMPARE_DG01 = 6;

  /**
   * Mask for Compare DG01 (eID): <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_COMPARE_DG01 = (byte)0x01;

  /**
   * Name for Compare DG01 (eID): <code>Compare DG01 (eID)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_COMPARE_DG01 = "Compare DG01 (eID): "
                                                              + EIDConstants.EID_NAME_DG01_DOCUMENT_TYPE;

  /**
   * Byte index for Read DG16 (eID): <code>7</code>.
   */
  static final int ACCESS_RIGHT_INDEX_READ_DG16 = 7;

  /**
   * Mask for Read DG16 (eID): <code>0x80</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG16 = (byte)0x80;

  /**
   * Name for Read DG16 (eID): <code>Read DG16 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG16 = "Read DG16 (eID): "
                                                           + EIDConstants.EID_NAME_DG16_RFU04;

  /**
   * Byte index for Read DG15 (eID): <code>7</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG15 = 7;

  /**
   * Mask for Read DG15 (eID): <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG15 = (byte)0x40;

  /**
   * Name for Read DG15 (eID): <code>Read DG15 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG15 = "Read DG15 (eID): "
                                                           + EIDConstants.EID_NAME_DG15_DATE_OF_ISSUANCE;

  /**
   * Byte index for Read DG14 (eID): <code>7</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG14 = 7;

  /**
   * Mask for Read DG14 (eID): <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG14 = (byte)0x20;

  /**
   * Name for Read DG14 (eID): <code>Read DG14 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG14 = "Read DG14 (eID): "
                                                           + EIDConstants.EID_NAME_DG14_WRITTEN_SIGNATURE;

  /**
   * Byte index for Read DG13 (eID): <code>7</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG13 = 7;

  /**
   * Mask for Read DG13 (eID): <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG13 = (byte)0x10;

  /**
   * Name for Read DG13 (eID): <code>Read DG13 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG13 = "Read DG13 (eID): "
                                                           + EIDConstants.EID_NAME_DG13_BIRTH_NAME;

  /**
   * Byte index for Read DG12 (eID): <code>7</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG12 = 7;

  /**
   * Mask for Read DG12 (eID): <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG12 = (byte)0x08;

  /**
   * Name for Read DG12 (eID): <code>Read DG12 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG12 = "Read DG12 (eID): "
                                                           + EIDConstants.EID_NAME_DG12_OPTIONAL_DATA_R;

  /**
   * Byte index for Read DG11 (eID): <code>7</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG11 = 7;

  /**
   * Mask for Read DG11 (eID): <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG11 = (byte)0x04;

  /**
   * Name for Read DG11 (eID): <code>Read DG11 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG11 = "Read DG11 (eID): "
                                                           + EIDConstants.EID_NAME_DG11_SEX;

  /**
   * Byte index for Read DG10 (eID): <code>7</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG10 = 7;

  /**
   * Mask for Read DG10 (eID): <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG10 = (byte)0x02;

  /**
   * Name for Read DG10 (eID): <code>Read DG10 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG10 = "Read DG10 (eID): "
                                                           + EIDConstants.EID_NAME_DG10_NATIONALITY;

  /**
   * Byte index for Read DG09 (eID): <code>7</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG09 = 7;

  /**
   * Mask for Read DG09 (eID): <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG09 = (byte)0x01;

  /**
   * Name for Read DG09 (eID): <code>Read DG09 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG09 = "Read DG09 (eID): "
                                                           + EIDConstants.EID_NAME_DG09_PLACE_OF_BIRTH;

  /**
   * Byte index for Read DG08 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG08 = 8;

  /**
   * Mask for Read DG08 (eID): <code>0x80</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG08 = (byte)0x80;

  /**
   * Name for Read DG08 (eID): <code>Read DG08 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG08 = "Read DG08 (eID): "
                                                           + EIDConstants.EID_NAME_DG08_DATE_OF_BIRTH;

  /**
   * Byte index for Read DG07 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG07 = 8;

  /**
   * Mask for Read DG07 (eID): <code>0x40</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG07 = (byte)0x40;

  /**
   * Name for Read DG07 (eID): <code>Read DG07 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG07 = "Read DG07 (eID): "
                                                           + EIDConstants.EID_NAME_DG07_ACADEMIC_TITLE;

  /**
   * Byte index for Read DG06 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG06 = 8;

  /**
   * Mask for Read DG06 (eID): <code>0x20</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG06 = (byte)0x20;

  /**
   * Name for Read DG06 (eID): <code>Read DG06 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG06 = "Read DG06 (eID): "
                                                           + EIDConstants.EID_NAME_DG06_NOM_DE_PLUME;

  /**
   * Byte index for Read DG05 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG05 = 8;

  /**
   * Mask for Read DG05 (eID): <code>0x10</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG05 = (byte)0x10;

  /**
   * Name for Read DG05 (eID): <code>Read DG05 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG05 = "Read DG05 (eID): "
                                                           + EIDConstants.EID_NAME_DG05_FAMILY_NAMES;

  /**
   * Byte index for Read DG04 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG04 = 8;

  /**
   * Mask for Read DG04 (eID): <code>0x08</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG04 = (byte)0x08;

  /**
   * Name for Read DG04 (eID): <code>Read DG04 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG04 = "Read DG04 (eID): "
                                                           + EIDConstants.EID_NAME_DG04_GIVEN_NAMES;

  /**
   * Byte index for Read DG03 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG03 = 8;

  /**
   * Mask for Read DG03 (eID): <code>0x04</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG03 = (byte)0x04;

  /**
   * Name for Read DG03 (eID): <code>Read DG03 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG03 = "Read DG03 (eID): "
                                                           + EIDConstants.EID_NAME_DG03_DATE_OF_EXPIRY;

  /**
   * Byte index for Read DG02 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG02 = 8;

  /**
   * Mask for Read DG02 (eID): <code>0x02</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG02 = (byte)0x02;

  /**
   * Name for Read DG02 (eID): <code>Read DG02 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG02 = "Read DG02 (eID): "
                                                           + EIDConstants.EID_NAME_DG02_ISSUING_STATE;

  /**
   * Byte index for Read DG01 (eID): <code>8</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG01 = 8;

  /**
   * Mask for Read DG01 (eID): <code>0x01</code>.
   */
  static final byte ACCESS_RIGHT_MASK_READ_DG01 = (byte)0x01;

  /**
   * Name for Read DG01 (eID): <code>Read DG01 (eID)</code>.
   */
  static final String ACCESS_RIGHT_NAME_READ_DG01 = "Read DG01 (eID): "
                                                           + EIDConstants.EID_NAME_DG01_DOCUMENT_TYPE;

  /**
   * Constant list of access roles (dummy).
   */
  static final List<BitIdentifier> ACCESS_ROLES_LIST = Collections.unmodifiableList(new ArrayList<BitIdentifier>());

  /**
   * Constant list of access rights.
   */
  static final List<BitIdentifier> ACCESS_RIGHTS_LIST = Collections.unmodifiableList(Arrays.asList((BitIdentifier[])AccessRightEnum.values()));

  private ATEidAccessConstants()
  {}
}
