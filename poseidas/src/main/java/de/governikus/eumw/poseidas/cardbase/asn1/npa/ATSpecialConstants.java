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

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialFunctions.AccessRightEnum;


public final class ATSpecialConstants
{

  /**
   * Suffix of OID for Authentication Terminal extension Special Functions: <code>.2</code>.
   */
  private static final String OID_SUFFIX_SPECIAL_FUNCTIONS = ".2";

  /**
   * Base OID of access rights for Authentication Terminal extension Special Functions:
   * <code>0.4.0.127.0.7.3.1.2.2.2</code>.
   */
  public static final String OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIAL_FUNCTIONS = ATConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL
                                                                                                    + OID_SUFFIX_SPECIAL_FUNCTIONS;

  /**
   * Count of ASN.1 value bytes: <code>1</code>.
   */
  public static final int VALUE_BYTE_COUNT = 1;


  /**
   * Byte index for PSC: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_PSC = 0;

  /**
   * Mask for PSC: <code>0x80</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_PSC = (byte)0x80;

  /**
   * Name for PSC: <code>Pseudonymous Signature (Credentials)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_PSC = "Pseudonymous Signature (Credentials)";

  /**
   * Byte index for PSM: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_PSM = 0;

  /**
   * Mask for PSM: <code>0x40</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_PSM = (byte)0x40;

  /**
   * Name for PSM: <code>Pseudonymous Signature (Message)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_PSM = "Pseudonymous Signature (Message)";

  /**
   * Byte index for PSA: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_PSA = 0;

  /**
   * Mask for PSA: <code>0x20</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_PSA = (byte)0x20;

  /**
   * Name for PSA: <code>Pseudonymous Signature (Authentication)</code>.
   */
  public static final String ACCESS_RIGHT_NAME_PSA = "Pseudonymous Signature (Authentication)";

  /**
   * Byte index for Restricted Identification: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_RI = 0;

  /**
   * Mask for Restricted Identification: <code>0x10</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_RI = (byte)0x10;

  /**
   * Name for Restricted Identification: <code>Restricted Identification</code>.
   */
  public static final String ACCESS_RIGHT_NAME_RI = "Restricted Identification";

  /**
   * Byte index for Municipality ID Verification: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_MUNICIPALITY_ID_VERIFICATION = 0;

  /**
   * Mask for Municipality ID Verification: <code>0x02</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_MUNICIPALITY_ID_VERIFICATION = (byte)0x02;

  /**
   * Name for Municipality ID Verification: <code>Municipality ID Verification</code>.
   */
  public static final String ACCESS_RIGHT_NAME_MUNICIPALITY_ID_VERIFICATION = "Municipality ID Verification";

  /**
   * Byte index for Age Verification: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_AGE_VERIFICATION = 0;

  /**
   * Mask for Age Verification: <code>0x01</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_AGE_VERIFICATION = (byte)0x01;

  /**
   * Name for Age Verification: <code>Age Verification</code>.
   */
  public static final String ACCESS_RIGHT_NAME_AGE_VERIFICATION = "Age Verification";

  /**
   * Constant list of access roles (dummy).
   */
  public static final List<BitIdentifier> ACCESS_ROLES_LIST = Collections.unmodifiableList(new ArrayList<BitIdentifier>());

  /**
   * Constant list of access rights.
   */
  public static final List<BitIdentifier> ACCESS_RIGHTS_LIST = Collections.unmodifiableList(Arrays.asList((BitIdentifier[])AccessRightEnum.values()));

  private ATSpecialConstants()
  {}
}
