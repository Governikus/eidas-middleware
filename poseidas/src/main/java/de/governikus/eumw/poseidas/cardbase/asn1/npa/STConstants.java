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
 * Constants used by {@link STConstants}.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class STConstants
{

  /**
   * Suffix of OID for Signature Terminal: <tt>.3</tt>.
   * 
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_SIGNATURE_TERMINAL
   */
  public static final String OID_SUFFIX_SIGNATURE_TERMINAL = ".3";

  /**
   * Base OID of access roles and rights for Signature Terminal: <tt>0.4.0.127.0.7.3.1.2.3</tt>.
   * 
   * @see AccessRoleAndRights#OID_ACCESS_ROLE_AND_RIGHTS
   * @see #OID_SUFFIX_SIGNATURE_TERMINAL
   * @see SignatureTerminals#getOIDString()
   */
  public static final String OID_ACCESS_ROLE_AND_RIGHTS_SIGNATURE_TERMINAL = AccessRoleAndRights.OID_ACCESS_ROLE_AND_RIGHTS
                                                                             + OID_SUFFIX_SIGNATURE_TERMINAL;

  /**
   * Constant of OID related to SignatureTerminals.
   * 
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_SIGNATURE_TERMINAL
   */
  public static final OID OID_SIGNATURE_TERMINAL = new OID(OID_ACCESS_ROLE_AND_RIGHTS_SIGNATURE_TERMINAL);

  /**
   * Count of ASN.1 value bytes: <code>1</code>.
   */
  public static final int VALUE_BYTE_COUNT = 1;

  /**
   * Constant of role mask for DV (Accreditation Body): <code>0x80</code>.
   * 
   * @see SignatureTerminals.AccessRoleEnum#DV_ACCREDITATION_BODY
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK_80
   */
  public static final byte ACCESS_ROLE_MASK_DV_ACCREDITATION_BODY = BaseAccessRoleAndRights.ACCESS_ROLE_MASK_80;

  /**
   * Constant of role name for DV (Accreditation Body): <tt>DV (Accreditation Body)</tt>.
   * 
   * @see SignatureTerminals.AccessRoleEnum#DV_ACCREDITATION_BODY
   */
  public static final String ACCESS_ROLE_NAME_DV_ACCREDITATION_BODY = "DV (Accreditation Body)";

  /**
   * Constant of role mask for DV (Certification Service Provider): <code>0x40</code>.
   * 
   * @see SignatureTerminals.AccessRoleEnum#DV_CERTIFICATION_SERVICE_PROVIDER
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK_40
   */
  public static final byte ACCESS_ROLE_MASK_DV_CERTIFICATION_SERVICE_PROVIDER = BaseAccessRoleAndRights.ACCESS_ROLE_MASK_40;

  /**
   * Constant of role name for DV (Certification Service Provider):
   * <tt>DV (Certification Service Provider)</tt>.
   * 
   * @see SignatureTerminals.AccessRoleEnum#DV_CERTIFICATION_SERVICE_PROVIDER
   */
  public static final String ACCESS_ROLE_NAME_DV_CERTIFICATION_SERVICE_PROVIDER = "DV (Certification Service Provider)";

  /**
   * Constant of role mask for Signature Terminal: <code>0x00</code>.
   * 
   * @see SignatureTerminals.AccessRoleEnum#SIGNATURE_TERMINAL
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK_00
   */
  public static final byte ACCESS_ROLE_MASK_SIGNATURE_TERMINAL = BaseAccessRoleAndRights.ACCESS_ROLE_MASK_00;

  /**
   * Constant of role name for Signature Terminal: <tt>Signature Terminal</tt>.
   * 
   * @see SignatureTerminals.AccessRoleEnum#SIGNATURE_TERMINAL
   */
  public static final String ACCESS_ROLE_NAME_SIGNATURE_TERMINAL = "Signature Terminal";

  /**
   * Constant of right mask for eSign Generate Qualified Electronic Signature: <code>0x01</code>.
   * 
   * @see SignatureTerminals.AccessRightEnum#ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE
   */
  public static final byte ACCESS_RIGHT_MASK_ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE = (byte)0x02;

  /**
   * Constant of right name for eSign Generate Qualified Electronic Signature:
   * <tt>eSign Generate Qualified Electronic Signature</tt>.
   * 
   * @see SignatureTerminals.AccessRightEnum#ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE
   */
  public static final String ACCESS_RIGHT_NAME_ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE = "eSign Generate Qualified Electronic Signature";

  /**
   * Constant of right mask for eSign Generate Electronic Signature: <code>0x02</code>.
   * 
   * @see SignatureTerminals.AccessRightEnum#ESIGN_GENERATE_ELECTRONIC_SIGNATURE
   */
  public static final byte ACCESS_RIGHT_MASK_ESIGN_GENERATE_ELECTRONIC_SIGNATURE = (byte)0x01;

  /**
   * Constant of right name for eSign Generate Electronic Signature:
   * <tt>eSign Generate Electronic Signature</tt>.
   * 
   * @see SignatureTerminals.AccessRightEnum#ESIGN_GENERATE_ELECTRONIC_SIGNATURE
   */
  public static final String ACCESS_RIGHT_NAME_ESIGN_GENERATE_ELECTRONIC_SIGNATURE = "eSign Generate Electronic Signature";

  private STConstants()
  {}
}
