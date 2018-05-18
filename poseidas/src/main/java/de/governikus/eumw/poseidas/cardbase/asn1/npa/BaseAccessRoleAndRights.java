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

import java.io.IOException;
import java.util.List;


/**
 * Base access role and rights for Inspection Systems and Authentication Terminal used by
 * {@link CertificateHolderAuthorizationTemplate}.
 * 
 * @see InspectionSystems
 * @see AuthenticationTerminals
 * @author Jens Wothe, jw@bos-bremen.de
 */
public abstract class BaseAccessRoleAndRights extends AccessRoleAndRights
{

  /**
   * Constant of role mask for DV (official domestic): {@link AccessRoleAndRights#ACCESS_ROLE_MASK_80}.
   * 
   * @see InspectionSystems.AccessRoleEnum#DV_OFFICIAL_DOMESTIC
   * @see AuthenticationTerminals.AccessRoleEnum#DV_OFFICIAL_DOMESTIC
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK_80
   */
  private static final byte ROLE_MASK_DV_OFFICIAL_DOMESTIC = ACCESS_ROLE_MASK_80;

  /**
   * Constant of role name for DV (official domestic): <tt>DV (official domestic)</tt>.
   * 
   * @see InspectionSystems.AccessRoleEnum#DV_OFFICIAL_DOMESTIC
   * @see AuthenticationTerminals.AccessRoleEnum#DV_OFFICIAL_DOMESTIC
   */
  private static final String ROLE_NAME_DV_OFFICIAL_DOMESTIC = "DV (official domestic)";

  /**
   * @see InspectionSystems.AccessRoleEnum#DV_OFFICIAL_FOREIGN
   * @see AuthenticationTerminals.AccessRoleEnum#DV_OFFICIAL_FOREIGN
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK_40
   */
  private static final byte ROLE_MASK_DV_OFFICIAL_FOREIGN = ACCESS_ROLE_MASK_40;

  /**
   * Constant of role name for DV (official foreign): <tt>DV (official foreign)</tt>.
   * 
   * @see InspectionSystems.AccessRoleEnum#DV_OFFICIAL_FOREIGN
   * @see AuthenticationTerminals.AccessRoleEnum#DV_OFFICIAL_FOREIGN
   */
  private static final String ROLE_NAME_DV_OFFICIAL_FOREIGN = "DV (official foreign)";

  /**
   * Role identifier DV (official domestic).
   * 
   * @see InspectionSystems.AccessRoleEnum#DV_OFFICIAL_DOMESTIC
   * @see AuthenticationTerminals.AccessRoleEnum#DV_OFFICIAL_DOMESTIC
   * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte, byte)
   * @see #ROLE_NAME_DV_OFFICIAL_DOMESTIC
   * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK
   * @see #ROLE_MASK_DV_OFFICIAL_DOMESTIC
   */
  static final BitIdentifier IDENTIFIER_DV_OFFICIAL_DOMESTIC = new BitIdentifierImpl(
                                                                                            ROLE_NAME_DV_OFFICIAL_DOMESTIC,
                                                                                            ACCESS_ROLE_BYTE_INDEX,
                                                                                            ACCESS_ROLE_MASK,
                                                                                            ROLE_MASK_DV_OFFICIAL_DOMESTIC);

  /**
   * Role identifier DV (official foreign).
   * 
   * @see InspectionSystems.AccessRoleEnum#DV_OFFICIAL_FOREIGN
   * @see AuthenticationTerminals.AccessRoleEnum#DV_OFFICIAL_FOREIGN
   * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte, byte)
   * @see #ROLE_NAME_DV_OFFICIAL_FOREIGN
   * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK
   * @see #ROLE_MASK_DV_OFFICIAL_FOREIGN
   */
  static final BitIdentifier IDENTIFIER_DV_OFFICIAL_FOREIGN = new BitIdentifierImpl(
                                                                                           ROLE_NAME_DV_OFFICIAL_FOREIGN,
                                                                                           ACCESS_ROLE_BYTE_INDEX,
                                                                                           ACCESS_ROLE_MASK,
                                                                                           ROLE_MASK_DV_OFFICIAL_FOREIGN);

  /**
   * Constructor.
   * 
   * @param bytes bytes of ASN.1 object
   * @param valueByteCount count of value bytes expected by implementation
   * @param definedAccessRolesIdentifierList list of defined access roles, <code>null</code> or empty list not
   *          permitted
   * @param definedAccessRightsIdentifierList list of defined access rights, <code>null</code> or empty list
   *          not permitted
   * @throws IOException if reading of stream fails
   * @see AccessRoleAndRights#AccessRoleAndRights(byte[], int, List, List)
   */
  BaseAccessRoleAndRights(byte[] bytes,
                                 int valueByteCount,
                                 List<BitIdentifier> definedAccessRolesIdentifierList,
                                 List<BitIdentifier> definedAccessRightsIdentifierList) throws IOException
  {
    super(bytes, valueByteCount, definedAccessRolesIdentifierList, definedAccessRightsIdentifierList);
  }

}
