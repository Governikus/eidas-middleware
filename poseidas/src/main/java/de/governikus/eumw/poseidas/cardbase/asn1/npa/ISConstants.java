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

import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * Constants used by {@link InspectionSystems}.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class ISConstants
{

  /**
   * Suffix of OID for Inspection System: <tt>.1</tt>.
   * 
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_INSPECTION_SYSTEM
   */
  public static final String OID_SUFFIX_INSPECTION_SYSTEM = ".1";

  /**
   * Base OID of access roles and rights for Inspection System: <tt>0.4.0.127.0.7.3.1.2.1</tt>.
   * 
   * @see AccessRoleAndRights#OID_ACCESS_ROLE_AND_RIGHTS
   * @see #OID_SUFFIX_INSPECTION_SYSTEM
   * @see InspectionSystems#getOIDString()
   */
  public static final String OID_ACCESS_ROLE_AND_RIGHTS_INSPECTION_SYSTEM = AccessRoleAndRights.OID_ACCESS_ROLE_AND_RIGHTS
                                                                            + OID_SUFFIX_INSPECTION_SYSTEM;

  /**
   * Constant of OID related to InspectionSystems.
   * 
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_INSPECTION_SYSTEM
   */
  public static final OID OID_INSPECTION_SYSTEMS = new OID(OID_ACCESS_ROLE_AND_RIGHTS_INSPECTION_SYSTEM);

  /**
   * Count of ASN.1 value bytes: <code>1</code>.
   */
  public static final int VALUE_BYTE_COUNT = 1;

  /**
   * Constant of role mask for Inspection System: <code>0x00</code>.
   * 
   * @see InspectionSystems.AccessRoleEnum#INSPECTION_SYSTEM
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK_00
   */
  public static final byte ROLE_MASK_INSPECTION_SYSTEM = BaseAccessRoleAndRights.ACCESS_ROLE_MASK_00;

  /**
   * Constant of role name for Inspection System: <tt>Inspection System</tt>.
   * 
   * @see InspectionSystems.AccessRoleEnum#INSPECTION_SYSTEM
   */
  public static final String ROLE_NAME_INSPECTION_SYSTEM = "Inspection System";

  /**
   * Constant of right mask for read access of eID application: <code>0x20</code>.
   * 
   * @see InspectionSystems.AccessRightEnum#READ_ACCESS_EID_APPLICATION
   */
  public static final byte ACCESS_RIGHT_MASK_READ_EID_APPLICATION = (byte)0x20;

  /**
   * Constant of right name for read access of eID application: <tt>Read access to eID application</tt>.
   * 
   * @see InspectionSystems.AccessRightEnum#READ_ACCESS_EID_APPLICATION
   */
  public static final String ACCESS_RIGHT_NAME_READ_ACCESS_EID_APPLICATION = "Read access to eID application";

  /**
   * Constant of right mask for read access of ePassport application DG4: <code>0x02</code>.
   * 
   * @see InspectionSystems.AccessRightEnum#READ_ACCESS_EPASSPORT_DG4
   */
  public static final byte ACCESS_RIGHT_MASK_READ_EPASSPORT_DG4 = (byte)0x02;

  /**
   * Constant of right name for read access of ePassport application DG4:
   * <tt>Read access to ePassport application: DG4 (Iris)</tt>.
   * 
   * @see InspectionSystems.AccessRightEnum#READ_ACCESS_EPASSPORT_DG4
   */
  public static final String ACCESS_RIGHT_NAME_READ_ACCESS_EPASSPORT_DG4 = "Read access to ePassport application: DG4 (Iris)";

  /**
   * Constant of right mask for read access of ePassport application DG3: <code>0x01</code>.
   * 
   * @see InspectionSystems.AccessRightEnum#READ_ACCESS_EPASSPORT_DG4
   */
  public static final byte ACCESS_RIGHT_MASK_READ_EPASSPORT_DG3 = (byte)0x01;

  /**
   * Constant of right name for read access of ePassport application DG3:
   * <tt>Read access to ePassport application: DG3 (Fingerprint)</tt>.
   * 
   * @see InspectionSystems.AccessRightEnum#READ_ACCESS_EPASSPORT_DG3
   */
  public static final String ACCESS_RIGHT_NAME_READ_ACCESS_EPASSPORT_DG3 = "Read access to ePassport application: DG3 (Fingerprint)";

  private ISConstants()
  {}
}
