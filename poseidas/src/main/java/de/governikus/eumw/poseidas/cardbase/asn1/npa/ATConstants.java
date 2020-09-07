/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.AuthenticationTerminals.AccessRightEnum;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.AuthenticationTerminals.AccessRoleEnum;
import de.governikus.eumw.poseidas.cardbase.constants.EIDConstants;


/**
 * Constants used by {@link AuthenticationTerminals}.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ATConstants
{

  /**
   * Suffix of OID for Authentication Terminal: <tt>.2</tt>.
   *
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL
   */
  public static final String OID_SUFFIX_AUTHENTICATION_TERMINAL = ".2";

  /**
   * Base OID of access roles and rights for Authentication Terminal: <tt>0.4.0.127.0.7.3.1.2.2</tt>.
   *
   * @see AccessRoleAndRights#OID_ACCESS_ROLE_AND_RIGHTS
   * @see #OID_SUFFIX_AUTHENTICATION_TERMINAL
   * @see InspectionSystems#getOIDString()
   */
  public static final String OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL = AccessRoleAndRights.OID_ACCESS_ROLE_AND_RIGHTS
                                                                                  + OID_SUFFIX_AUTHENTICATION_TERMINAL;

  /**
   * Constant of OID related to AuthenticationTerminals.
   *
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL
   */
  public static final OID OID_AUTHENTICATION_TERMINALS = new OID(OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL);

  /**
   * Count of ASN.1 value bytes: <code>5</code>.
   */
  public static final int VALUE_BYTE_COUNT = 5;

  /**
   * Constant of role mask Authentication Terminal: <code>0x00</code>.
   *
   * @see AuthenticationTerminals.AccessRoleEnum#AUTHENTICATION_TERMINAL
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK_00
   */
  public static final byte ACCESS_ROLE_MASK_AUTHENTICATION_TERMINAL = AccessRoleAndRights.ACCESS_ROLE_MASK_00;

  /**
   * Constant of role name Authentication Terminal: <tt>Authentication Terminal</tt>.
   *
   * @see AuthenticationTerminals.AccessRoleEnum#AUTHENTICATION_TERMINAL
   */
  public static final String ACCESS_ROLE_NAME_AUTHENTICATION_TERMINAL = "Authentication Terminal";

  /**
   * Constant of byte index for right Write DG17 (eID): <code>0</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG17
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_DG17 = 0;

  /**
   * Constant of right mask Write DG17 (eID): <code>0x20</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG17
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_DG17 = (byte)0x20;

  /**
   * Constant of right name Write DG17 (eID): <tt>Write DG17 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG17
   * @see EIDConstants#EID_NAME_DG17_PLACE_OF_RESIDENCE
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_DG17 = "Write DG17 (eID): "
                                                            + EIDConstants.EID_NAME_DG17_PLACE_OF_RESIDENCE;

  /**
   * Constant of byte index for right Write DG18 (eID): <code>0</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG18
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_DG18 = 0;

  /**
   * Constant of right mask Write DG18 (eID): <code>0x10</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG18
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_DG18 = (byte)0x10;

  /**
   * Constant of right name Write DG18 (eID): <tt>Write DG18 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG18
   * @see EIDConstants#EID_NAME_DG18_MUNICIPALITY_ID
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_DG18 = "Write DG18 (eID): "
                                                            + EIDConstants.EID_NAME_DG18_MUNICIPALITY_ID;

  /**
   * Constant of byte index for right Write DG19 (eID): <code>0</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG19
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_DG19 = 0;

  /**
   * Constant of right mask Write DG19 (eID): <code>0x08</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG19
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_DG19 = (byte)0x08;

  /**
   * Constant of right name Write DG19 (eID): <tt>Write DG19 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG19
   * @see EIDConstants#EID_NAME_DG19_RESIDENCE_PERMIT_I
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_DG19 = "Write DG19 (eID): "
                                                            + EIDConstants.EID_NAME_DG19_RESIDENCE_PERMIT_I;

  /**
   * Constant of byte index for right Write DG20 (eID): <code>0</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG20
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_DG20 = 0;

  /**
   * Constant of right mask Write DG20 (eID): <code>0x04</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG20
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_DG20 = (byte)0x04;

  /**
   * Constant of right name Write DG20 (eID): <tt>Write DG20 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG20
   * @see EIDConstants#EID_NAME_DG20_RESIDENCE_PERMIT_II
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_DG20 = "Write DG20 (eID): "
                                                            + EIDConstants.EID_NAME_DG20_RESIDENCE_PERMIT_II;

  /**
   * Constant of byte index for right Write DG21 (eID): <code>0</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG21
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_DG21 = 0;

  /**
   * Constant of right mask Write DG21 (eID): <code>0x02</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG21
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_DG21 = (byte)0x02;

  /**
   * Constant of right name Write DG21 (eID): <tt>Write DG21 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG21
   * @see EIDConstants#EID_NAME_DG21_PHONE_NUMBER
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_DG21 = "Write DG21 (eID): "
                                                            + EIDConstants.EID_NAME_DG21_PHONE_NUMBER;

  /**
   * Constant of byte index for right Write DG22 (eID): <code>0</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG22
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_DG22 = 0;

  /**
   * Constant of right mask Write DG22 (eID): <code>0x01</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG22
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_DG22 = (byte)0x01;

  /**
   * Constant of right name Write DG22 (eID): <tt>Write DG22 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#WRITE_DG22
   * @see EIDConstants#EID_NAME_DG22_EMAIL_ADDRESS
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_DG22 = "Write DG22 (eID): "
                                                            + EIDConstants.EID_NAME_DG22_EMAIL_ADDRESS;

  /**
   * Constant of byte index for right PSA: <code>1</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PSA
   */
  public static final int ACCESS_RIGHT_INDEX_PSA = 1;

  /**
   * Constant of right mask PSA: <code>0x40</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PSA
   */
  public static final byte ACCESS_RIGHT_MASK_PSA = (byte)0x40;

  /**
   * Constant of right name PSA: <tt>Pseudonymous Signature (Authentication)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PSA
   */
  public static final String ACCESS_RIGHT_NAME_PSA = "Pseudonymous Signature (Authentication)";

  /**
   * Constant of byte index for right Read DG22 (eID): <code>1</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG22
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG22 = 1;

  /**
   * Constant of right mask Read DG22 (eID): <code>0x20</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG22
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG22 = (byte)0x20;

  /**
   * Constant of right name Read DG22 (eID): <tt>Read DG22 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG22
   * @see EIDConstants#EID_NAME_DG22_EMAIL_ADDRESS
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG22 = "Read DG22 (eID): "
                                                           + EIDConstants.EID_NAME_DG22_EMAIL_ADDRESS;

  /**
   * Constant of byte index for right Read DG21 (eID): <code>1</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG21
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG21 = 1;

  /**
   * Constant of right mask Read DG21 (eID): <code>0x10</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG21
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG21 = (byte)0x10;

  /**
   * Constant of right name Read DG21 (eID): <tt>Read DG21 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG21
   * @see EIDConstants#EID_NAME_DG21_PHONE_NUMBER
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG21 = "Read DG21 (eID): "
                                                           + EIDConstants.EID_NAME_DG21_PHONE_NUMBER;

  /**
   * Constant of byte index for right Read DG20 (eID): <code>1</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG20
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG20 = 1;

  /**
   * Constant of right mask Read DG20 (eID): <code>0x08</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG20
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG20 = (byte)0x08;

  /**
   * Constant of right name Read DG20 (eID): <tt>Read DG20 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG20
   * @see EIDConstants#EID_NAME_DG20_RESIDENCE_PERMIT_II
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG20 = "Read DG20 (eID): "
                                                           + EIDConstants.EID_NAME_DG20_RESIDENCE_PERMIT_II;

  /**
   * Constant of byte index for right Read DG19 (eID): <code>1</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG19
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG19 = 1;

  /**
   * Constant of right mask Read DG19 (eID): <code>0x04</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG19
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG19 = (byte)0x04;

  /**
   * Constant of right name Read DG19 (eID): <tt>Read DG19 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG19
   * @see EIDConstants#EID_NAME_DG19_RESIDENCE_PERMIT_I
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG19 = "Read DG19 (eID): "
                                                           + EIDConstants.EID_NAME_DG19_RESIDENCE_PERMIT_I;

  /**
   * Constant of byte index for right Read DG18 (eID): <code>1</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG18
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG18 = 1;

  /**
   * Constant of right mask Read DG18 (eID): <code>0x02</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG18
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG18 = (byte)0x02;

  /**
   * Constant of right name Read DG18 (eID): <tt>Read DG18 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG18
   * @see EIDConstants#EID_NAME_DG18_MUNICIPALITY_ID
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG18 = "Read DG18 (eID): "
                                                           + EIDConstants.EID_NAME_DG18_MUNICIPALITY_ID;

  /**
   * Constant of byte index for right Read DG17 (eID): <code>1</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG17
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG17 = 1;

  /**
   * Constant of right mask Read DG17 (eID): <code>0x01</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG17
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG17 = (byte)0x01;

  /**
   * Constant of right name Read DG17 (eID): <tt>Read DG17 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG17
   * @see EIDConstants#EID_NAME_DG17_PLACE_OF_RESIDENCE
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG17 = "Read DG17 (eID): "
                                                           + EIDConstants.EID_NAME_DG17_PLACE_OF_RESIDENCE;

  /**
   * Constant of byte index for right Read DG16 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG16
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG16 = 2;

  /**
   * Constant of right mask Read DG16 (eID): <code>0x80</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG16
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG16 = (byte)0x80;

  /**
   * Constant of right name Read DG16 (eID): <tt>Read DG16 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG16
   * @see EIDConstants#EID_NAME_DG16_RFU04
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG16 = "Read DG16 (eID): "
                                                           + EIDConstants.EID_NAME_DG16_RFU04;

  /**
   * Constant of byte index for right Read DG15 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG15
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG15 = 2;

  /**
   * Constant of right mask Read DG15 (eID): <code>0x40</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG15
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG15 = (byte)0x40;

  /**
   * Constant of right name Read DG15 (eID): <tt>Date of Issuance (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG15
   * @see EIDConstants#EID_NAME_DG15_DATE_OF_ISSUANCE
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG15 = "Read DG15 (eID): "
                                                           + EIDConstants.EID_NAME_DG15_DATE_OF_ISSUANCE;

  /**
   * Constant of byte index for right Read DG14 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG14
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG14 = 2;

  /**
   * Constant of right mask Read DG14 (eID): <code>0x20</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG14
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG14 = (byte)0x20;

  /**
   * Constant of right name Read DG14 (eID): <tt>Read DG14 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG14
   * @see EIDConstants#EID_NAME_DG14_WRITTEN_SIGNATURE
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG14 = "Read DG14 (eID): "
                                                           + EIDConstants.EID_NAME_DG14_WRITTEN_SIGNATURE;

  /**
   * Constant of byte index for right Read DG13 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG13
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG13 = 2;

  /**
   * Constant of right mask Read DG13 (eID): <code>0x10</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG13
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG13 = (byte)0x10;

  /**
   * Constant of right name Read DG13 (eID): <tt>Read DG13 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG13
   * @see EIDConstants#EID_NAME_DG13_BIRTH_NAME
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG13 = "Read DG13 (eID): "
                                                           + EIDConstants.EID_NAME_DG13_BIRTH_NAME;

  /**
   * Constant of byte index for right Read DG12 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG12
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG12 = 2;

  /**
   * Constant of right mask Read DG12 (eID): <code>0x08</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG12
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG12 = (byte)0x08;

  /**
   * Constant of right name Read DG12 (eID): <tt>Read DG12 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG12
   * @see EIDConstants#EID_NAME_DG12_OPTIONAL_DATA_R
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG12 = "Read DG12 (eID): "
                                                           + EIDConstants.EID_NAME_DG12_OPTIONAL_DATA_R;

  /**
   * Constant of byte index for right Read DG11 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG11
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG11 = 2;

  /**
   * Constant of right mask Read DG11 (eID): <code>0x04</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG11
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG11 = (byte)0x04;

  /**
   * Constant of right name Read DG11 (eID): <tt>Read DG11 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG11
   * @see EIDConstants#EID_NAME_DG11_SEX
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG11 = "Read DG11 (eID): "
                                                           + EIDConstants.EID_NAME_DG11_SEX;

  /**
   * Constant of byte index for right Read DG10 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG10
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG10 = 2;

  /**
   * Constant of right mask Read DG10 (eID): <code>0x02</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG10
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG10 = (byte)0x02;

  /**
   * Constant of right name Read DG10 (eID): <tt>Read DG10 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG10
   * @see EIDConstants#EID_NAME_DG10_NATIONALITY
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG10 = "Read DG10 (eID): "
                                                           + EIDConstants.EID_NAME_DG10_NATIONALITY;

  /**
   * Constant of byte index for right Read DG9 (eID): <code>2</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG9
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG9 = 2;

  /**
   * Constant of right mask Read DG9 (eID): <code>0x01</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG9
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG9 = (byte)0x01;

  /**
   * Constant of right name Read DG9 (eID): <tt>Read DG9 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG9
   * @see EIDConstants#EID_NAME_DG09_PLACE_OF_BIRTH
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG9 = "Read DG9 (eID): "
                                                          + EIDConstants.EID_NAME_DG09_PLACE_OF_BIRTH;

  /**
   * Constant of byte index for right Read DG8 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG8
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG8 = 3;

  /**
   * Constant of right mask Read DG8 (eID): <code>0x80</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG8
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG8 = (byte)0x80;

  /**
   * Constant of right name Read DG8 (eID): <tt>Read DG8 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG8
   * @see EIDConstants#EID_NAME_DG08_DATE_OF_BIRTH
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG8 = "Read DG8 (eID): "
                                                          + EIDConstants.EID_NAME_DG08_DATE_OF_BIRTH;

  /**
   * Constant of byte index for right Read DG7 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG7
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG7 = 3;

  /**
   * Constant of right mask Read DG7 (eID): <code>0x40</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG7
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG7 = (byte)0x40;

  /**
   * Constant of right name Read DG7 (eID): <tt>Read DG7 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG7
   * @see EIDConstants#EID_NAME_DG07_ACADEMIC_TITLE
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG7 = "Read DG7 (eID): "
                                                          + EIDConstants.EID_NAME_DG07_ACADEMIC_TITLE;

  /**
   * Constant of byte index for right Read DG6 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG6
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG6 = 3;

  /**
   * Constant of right mask Read DG6 (eID): <code>0x20</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG6
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG6 = (byte)0x20;

  /**
   * Constant of right name Read DG6 (eID): <tt>Read DG6 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG6
   * @see EIDConstants#EID_FID_DG06_NOM_DE_PLUME
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG6 = "Read DG6 (eID): "
                                                          + EIDConstants.EID_NAME_DG06_NOM_DE_PLUME;

  /**
   * Constant of byte index for right Read DG5 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG5
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG5 = 3;

  /**
   * Constant of right mask Read DG5 (eID): <code>0x10</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG5
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG5 = (byte)0x10;

  /**
   * Constant of right name Read DG5 (eID): <tt>Read DG5 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG5
   * @see EIDConstants#EID_NAME_DG05_FAMILY_NAMES
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG5 = "Read DG5 (eID): "
                                                          + EIDConstants.EID_NAME_DG05_FAMILY_NAMES;

  /**
   * Constant of byte index for right Read DG4 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG4
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG4 = 3;

  /**
   * Constant of right mask Read DG4 (eID): <code>0x08</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG4
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG4 = (byte)0x08;

  /**
   * Constant of right name Read DG4 (eID): <tt>Read DG4 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG4
   * @see EIDConstants#EID_NAME_DG04_GIVEN_NAMES
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG4 = "Read DG4 (eID): "
                                                          + EIDConstants.EID_NAME_DG04_GIVEN_NAMES;

  /**
   * Constant of byte index for right Read DG3 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG3
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG3 = 3;

  /**
   * Constant of right mask Read DG3 (eID): <code>0x04</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG3
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG3 = (byte)0x04;

  /**
   * Constant of right name Read DG3 (eID): <tt>Read DG3 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG3
   * @see EIDConstants#EID_NAME_DG03_DATE_OF_EXPIRY
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG3 = "Read DG3 (eID): "
                                                          + EIDConstants.EID_NAME_DG03_DATE_OF_EXPIRY;

  /**
   * Constant of byte index for right Read DG2 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG2
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG2 = 3;

  /**
   * Constant of right mask Read DG2 (eID): <code>0x02</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG2
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG2 = (byte)0x02;

  /**
   * Constant of right name Read DG2 (eID): <tt>Read DG2 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG2
   * @see EIDConstants#EID_NAME_DG02_ISSUING_STATE
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG2 = "Read DG2 (eID): "
                                                          + EIDConstants.EID_NAME_DG02_ISSUING_STATE;

  /**
   * Constant of byte index for right Read DG1 (eID): <code>3</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG1
   */
  public static final int ACCESS_RIGHT_INDEX_READ_DG1 = 3;

  /**
   * Constant of right mask Read DG1 (eID): <code>0x01</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG1
   */
  public static final byte ACCESS_RIGHT_MASK_READ_DG1 = (byte)0x01;

  /**
   * Constant of right name Read DG1 (eID): <tt>Read DG1 (eID)</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#READ_DG1
   * @see EIDConstants#EID_NAME_DG01_DOCUMENT_TYPE
   */
  public static final String ACCESS_RIGHT_NAME_READ_DG1 = "Read DG1 (eID): "
                                                          + EIDConstants.EID_FID_DG01_DOCUMENT_TYPE;

  /**
   * Constant of byte index for right Install Qualified Certificate: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#INSTALL_QUALIFIED_CERTIFICATE
   */
  public static final int ACCESS_RIGHT_INDEX_INSTALL_QUALIFIED_CERTIFICATE = 4;

  /**
   * Constant of right mask Install Qualified Certificate: <code>0x80</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#INSTALL_QUALIFIED_CERTIFICATE
   */
  public static final byte ACCESS_RIGHT_MASK_INSTALL_QUALIFIED_CERTIFICATE = (byte)0x80;

  /**
   * Constant of right name Install Qualified Certificate: <tt>Install Qualified Certificate</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#INSTALL_QUALIFIED_CERTIFICATE
   */
  public static final String ACCESS_RIGHT_NAME_INSTALL_QUALIFIED_CERTIFICATE = "Install Qualified Certificate";

  /**
   * Constant of byte index for right Install Certificate: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#INSTALL_CERTIFICATE
   */
  public static final int ACCESS_RIGHT_INDEX_INSTALL_CERTIFICATE = 4;

  /**
   * Constant of right mask Install Certificate: <code>0x40</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#INSTALL_CERTIFICATE
   */
  public static final byte ACCESS_RIGHT_MASK_INSTALL_CERTIFICATE = (byte)0x40;

  /**
   * Constant of right name Install Certificate: <tt>Install Certificate</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#INSTALL_CERTIFICATE
   */
  public static final String ACCESS_RIGHT_NAME_INSTALL_CERTIFICATE = "Install Certificate";

  /**
   * Constant of byte index for right PIN Management: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PIN_MANAGEMENT
   */
  public static final int ACCESS_RIGHT_INDEX_PIN_MANAGEMENT = 4;

  /**
   * Constant of right mask PIN Management: <code>0x20</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PIN_MANAGEMENT
   */
  public static final byte ACCESS_RIGHT_MASK_PIN_MANAGEMENT = (byte)0x20;

  /**
   * Constant of right name PIN Management: <tt>PIN Management</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PIN_MANAGEMENT
   */
  public static final String ACCESS_RIGHT_NAME_PIN_MANAGEMENT = "PIN Management";

  /**
   * Constant of byte index for right CAN allowed: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#CAN_ALLOWED
   */
  public static final int ACCESS_RIGHT_INDEX_CAN_ALLOWED = 4;

  /**
   * Constant of right mask CAN allowed: <code>0x10</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#CAN_ALLOWED
   */
  public static final byte ACCESS_RIGHT_MASK_CAN_ALLOWED = (byte)0x10;

  /**
   * Constant of right name CAN allowed: <tt>CAN allowed</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#CAN_ALLOWED
   */
  public static final String ACCESS_RIGHT_NAME_CAN_ALLOWED = "CAN allowed";

  /**
   * Constant of byte index for right Privileged Terminal: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PRIVILEGED_TERMINAL
   */
  public static final int ACCESS_RIGHT_INDEX_PRIVILEGED_TERMINAL = 4;

  /**
   * Constant of right mask Privileged Terminal: <code>0x08</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PRIVILEGED_TERMINAL
   */
  public static final byte ACCESS_RIGHT_MASK_PRIVILEGED_TERMINAL = (byte)0x08;

  /**
   * Constant of right name Restricted Identification: <tt>Privileged Terminal</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#PRIVILEGED_TERMINAL
   */
  public static final String ACCESS_RIGHT_NAME_PRIVILEGED_TERMINAL = "Privileged Terminal";

  /**
   * Constant of byte index for right Restricted Identification: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#RESTRICTED_IDENTIFICATION
   */
  public static final int ACCESS_RIGHT_INDEX_RESTRICTED_IDENTIFICATION = 4;

  /**
   * Constant of right mask Restricted Identification: <code>0x04</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#RESTRICTED_IDENTIFICATION
   */
  public static final byte ACCESS_RIGHT_MASK_RESTRICTED_IDENTIFICATION = (byte)0x04;

  /**
   * Constant of right name Restricted Identification: <tt>Restricted Identification</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#RESTRICTED_IDENTIFICATION
   */
  public static final String ACCESS_RIGHT_NAME_RESTRICTED_IDENTIFICATION = "Restricted Identification";

  /**
   * Constant of byte index for right Community ID Identification: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#MUNICIPALITY_ID_VERIFICATION
   */
  public static final int ACCESS_RIGHT_INDEX_MUNICIPALITY_ID_VERIFICATION = 4;

  /**
   * Constant of right mask Community ID Identification: <code>0x02</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#MUNICIPALITY_ID_VERIFICATION
   */
  public static final byte ACCESS_RIGHT_MASK_MUNICIPALITY_ID_VERIFICATION = (byte)0x02;

  /**
   * Constant of right name Community ID Identification: <tt>Municipality ID Identification</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#MUNICIPALITY_ID_VERIFICATION
   */
  public static final String ACCESS_RIGHT_NAME_MUNICIPALITY_ID_VERIFICATION = "Municipality ID Identification";

  /**
   * Constant of byte index for right Age Verification: <code>4</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#AGE_VERIFICATION
   */
  public static final int ACCESS_RIGHT_INDEX_AGE_VERIFICATION = 4;

  /**
   * Constant of right mask Age Verification: <code>0x01</code>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#AGE_VERIFICATION
   */
  public static final byte ACCESS_RIGHT_MASK_AGE_VERIFICATION = (byte)0x01;

  /**
   * Constant of right name Age Verification: <tt>Age Verification</tt>.
   *
   * @see AuthenticationTerminals.AccessRightEnum#AGE_VERIFICATION
   */
  public static final String ACCESS_RIGHT_NAME_AGE_VERIFICATION = "Age Verification";

  /**
   * Constant list of access roles.
   *
   * @see AccessRoleEnum
   * @see AccessRoleEnum#values()
   */
  public static final List<BitIdentifier> ACCESS_ROLES_LIST = Collections.unmodifiableList(Arrays.asList((BitIdentifier[])AccessRoleEnum.values()));

  /**
   * Constant list of access rights.
   *
   * @see AccessRightEnum
   * @see AccessRightEnum#values()
   */
  public static final List<BitIdentifier> ACCESS_RIGHTS_LIST = Collections.unmodifiableList(Arrays.asList((BitIdentifier[])AccessRightEnum.values()));

  private ATConstants()
  {}

}
