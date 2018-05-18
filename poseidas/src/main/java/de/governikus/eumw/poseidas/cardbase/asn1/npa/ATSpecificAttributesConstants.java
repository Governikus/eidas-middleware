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

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributes.AccessRightEnum;


public final class ATSpecificAttributesConstants
{

  /**
   * Base OID of access rights for Authentication Terminal extension Specific Attributes:
   * <code>1.2.250.1.223.1001.1.3</code>.
   */
  public static final String OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL_SPECIFIC_ATTRIBUTES = "1.2.250.1.223.1001.1.3";

  /**
   * Count of ASN.1 value bytes: <code>1</code>.
   */
  public static final int VALUE_BYTE_COUNT = 1;


  /**
   * Name for Specific Attributes: <code>Include Specific Attributes to PSC</code>.
   */
  public static final String ACCESS_RIGHT_NAME_INCL_SPEC_ATTR = "Include Specific Attributes to PSC";

  /**
   * Byte index for Specific Attributes: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_INCL_SPEC_ATTR = 0;

  /**
   * Mask for Specific Attributes: <code>0x40</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_INCL_SPEC_ATTR = (byte)0x40;

  /**
   * Name for Access to all Terminal Sectors: <code>Access to all Terminal Sectors</code>.
   */
  public static final String ACCESS_RIGHT_NAME_ACCESS_TO_ALL_TERMINAL_SECTORS = "Access to all Terminal Sectors";

  /**
   * Byte index for Access to all Terminal Sectors: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_ACCESS_TO_ALL_TERMINAL_SECTORS = 0;

  /**
   * Mask for Access to all Terminal Sectors: <code>0x20</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_ACCESS_TO_ALL_TERMINAL_SECTORS = (byte)0x20;

  /**
   * Name for Delete Specific Attributes: <code>Delete Specific Attributes</code>.
   */
  public static final String ACCESS_RIGHT_NAME_DELETE_SPEC_ATT = "Delete Specific Attributes";

  /**
   * Byte index for Delete Specific Attributes: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_DELETE_SPEC_ATT = 0;

  /**
   * Mask for Delete Specific Attributes: <code>0x10</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_DELETE_SPEC_ATT = (byte)0x10;

  /**
   * Name for Write Specific Attribute: <code>Write Specific Attribute</code>.
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_SPEC_ATT = "Write Specific Attribute";

  /**
   * Byte index for Write Specific Attribute: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_SPEC_ATT = 0;

  /**
   * Mask for Write Specific Attribute: <code>0x08</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_SPEC_ATT = (byte)0x08;

  /**
   * Name for Read Specific Attribute: <code>Read Specific Attribute</code>.
   */
  public static final String ACCESS_RIGHT_NAME_READ_SPEC_ATT = "Read Specific Attribute";

  /**
   * Byte index for Read Specific Attribute: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_SPEC_ATT = 0;

  /**
   * Mask for Read Specific Attribute: <code>0x04</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_READ_SPEC_ATT = (byte)0x04;

  /**
   * Name for Write Attribute Request: <code>Write Attribute Request</code>.
   */
  public static final String ACCESS_RIGHT_NAME_WRITE_ATT_REQUEST = "Write Attribute Request";

  /**
   * Byte index for Write Attribute Request: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_WRITE_ATT_REQUEST = 0;

  /**
   * Mask for Write Attribute Request: <code>0x02</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_WRITE_ATT_REQUEST = (byte)0x02;

  /**
   * Name for Read Attribute Request: <code>Read Attribute Request</code>.
   */
  public static final String ACCESS_RIGHT_NAME_READ_ATT_REQUEST = "Read Attribute Request";

  /**
   * Byte index for Read Attribute Request: <code>0</code>.
   */
  public static final int ACCESS_RIGHT_INDEX_READ_ATT_REQUEST = 0;

  /**
   * Mask for Read Attribute Request: <code>0x01</code>.
   */
  public static final byte ACCESS_RIGHT_MASK_READ_ATT_REQUEST = (byte)0x01;



  /**
   * Constant list of access roles (dummy).
   */
  public static final List<BitIdentifier> ACCESS_ROLES_LIST = Collections.unmodifiableList(new ArrayList<BitIdentifier>());

  /**
   * Constant list of access rights.
   */
  public static final List<BitIdentifier> ACCESS_RIGHTS_LIST = Collections.unmodifiableList(Arrays.asList((BitIdentifier[])AccessRightEnum.values()));

  private ATSpecificAttributesConstants()
  {}
}
