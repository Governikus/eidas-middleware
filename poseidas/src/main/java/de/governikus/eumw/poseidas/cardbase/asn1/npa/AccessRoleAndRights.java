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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;


/**
 * Abstract base for access role and rights implementation used by
 * {@link CertificateHolderAuthorizationTemplate}.
 *
 * @see BaseAccessRoleAndRights
 * @see InspectionSystems
 * @see AuthenticationTerminals
 * @see SignatureTerminals
 * @author Jens Wothe, jw@bos-bremen.de
 */
public abstract class AccessRoleAndRights extends ASN1
{

  /**
   * Base OID of access roles and rights: <tt>0.4.0.127.0.7.3.1.2</tt>.
   *
   * @see InspectionSystems#getOIDString()
   * @see AuthenticationTerminals#getOIDString()
   * @see SignatureTerminals#getOIDString()
   */
  static final String OID_ACCESS_ROLE_AND_RIGHTS = "0.4.0.127.0.7.3.1.2";

  /**
   * Constant of index for role byte: <code>0</code>.
   */
  static final int ACCESS_ROLE_BYTE_INDEX = 0;

  /**
   * Constant of significant bits for role: <code>0xc0</code>.
   */
  static final byte ACCESS_ROLE_MASK = (byte)0xc0;

  /**
   * Constant of role CVCA: <code>0xc0</code>.
   *
   * @see #ACCESS_ROLE_MASK
   * @see InspectionSystems.AccessRoleEnum#CVCA
   * @see AuthenticationTerminals.AccessRoleEnum#CVCA
   * @see SignatureTerminals.AccessRoleEnum#CVCA
   */
  private static final byte ACCESS_ROLE_CVCA_MASK = (byte)0xc0;

  /**
   * Constant of role name CVCA: <tt>CVCA</tt>.
   *
   * @see InspectionSystems.AccessRoleEnum#CVCA
   * @see AuthenticationTerminals.AccessRoleEnum#CVCA
   * @see SignatureTerminals.AccessRoleEnum#CVCA
   */
  private static final String ACCESS_ROLE_NAME_CVCA = "CVCA";

  /**
   * Constant of role mask: <code>0x80</code>.
   */
  static final byte ACCESS_ROLE_MASK_80 = (byte)0x80;

  /**
   * Constant of role mask: <code>0x40</code>.
   */
  static final byte ACCESS_ROLE_MASK_40 = (byte)0x40;

  /**
   * Constant of role mask: <code>0x00</code>.
   */
  static final byte ACCESS_ROLE_MASK_00 = (byte)0x00;

  /**
   * Role identifier CVCA.
   *
   * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
   * @see AccessRoleAndRights#ACCESS_ROLE_NAME_CVCA
   * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
   * @see AccessRoleAndRights#ACCESS_ROLE_MASK
   * @see AccessRoleAndRights#ACCESS_ROLE_CVCA_MASK
   */
  static final BitIdentifier IDENTIFIER_CVCA = new BitIdentifierImpl(ACCESS_ROLE_NAME_CVCA,
                                                                     ACCESS_ROLE_BYTE_INDEX, ACCESS_ROLE_MASK,
                                                                     ACCESS_ROLE_CVCA_MASK);

  // list of defined access roles
  private final List<BitIdentifier> definedAccessRolesIdentifierList;

  // list of defined access rights
  private final List<BitIdentifier> definedAccessRightsIdentifierList;

  // list of access roles found
  private List<BitIdentifier> accessRolesIdentifierList = null;

  // list of access rights found
  private List<BitIdentifier> accessRightsIdentifierList = null;

  /**
   * Constructor.
   *
   * @param bytes bytes of
   * @param valueByteCount count of value bytes expected by implementation
   * @param definedAccessRolesIdentifierList list of defined access roles, <code>null</code> or empty list not
   *          permitted
   * @param definedAccessRightsIdentifierList list of defined access rights, <code>null</code> or empty list
   *          not permitted
   * @throws IOException if reading of stream fails
   * @see ASN1#ASN1(byte[])
   */
  AccessRoleAndRights(byte[] bytes,
                      int valueByteCount,
                      List<BitIdentifier> definedAccessRolesIdentifierList,
                      List<BitIdentifier> definedAccessRightsIdentifierList)
    throws IOException
  {
    // init ASN.1
    super(bytes);
    AssertUtil.equals(new BigInteger(new byte[]{ASN1EidConstants.TAG_DISCRETIONARY_DATA}),
                      super.getTag(),
                      "tag");
    // check count of bytes
    if (super.getValue() == null || super.getValue().length != valueByteCount)
    {
      throw new IllegalArgumentException("wrong count of value bytes: " + valueByteCount);
    }

    // check defined roles and rights
    if (definedAccessRolesIdentifierList == null)
    {
      throw new IllegalArgumentException("list of access roles not permitted as null");
    }
    if (definedAccessRightsIdentifierList == null || definedAccessRightsIdentifierList.isEmpty())
    {
      throw new IllegalArgumentException("list of access rights not permitted as null or empty list");
    }
    // make unmodifiable lists
    this.definedAccessRolesIdentifierList = Collections.unmodifiableList(new ArrayList<>(definedAccessRolesIdentifierList));
    this.definedAccessRightsIdentifierList = Collections.unmodifiableList(new ArrayList<>(definedAccessRightsIdentifierList));
    update();
  }

  /** {@inheritDoc} */
  @Override
  protected final void update()
  {
    // gets the value bytes for checks
    byte[] value = super.getValue();
    // initialize or clear list of roles
    this.accessRolesIdentifierList = new ArrayList<>();
    // check current roles
    for ( BitIdentifier tmp : this.definedAccessRolesIdentifierList )
    {
      if (tmp.accept(value))
      {
        this.accessRolesIdentifierList.add(tmp);
      }
    }
    this.accessRolesIdentifierList = Collections.unmodifiableList(this.accessRolesIdentifierList);
    // initialize or clear list of rights
    this.accessRightsIdentifierList = new ArrayList<>();
    // check current rights
    for ( BitIdentifier tmp : this.definedAccessRightsIdentifierList )
    {
      if (tmp.accept(value))
      {
        this.accessRightsIdentifierList.add(tmp);
      }
    }
    this.accessRightsIdentifierList = Collections.unmodifiableList(this.accessRightsIdentifierList);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return super.toString() + "(Roles: " + this.accessRolesIdentifierList + ", Rights: "
           + this.accessRightsIdentifierList + ")";
  }

  /**
   * Gets list of all known, defined rights.
   *
   * @return list of defined rights
   */
  public List<BitIdentifier> getDefinedAccessRightsList()
  {
    return this.definedAccessRightsIdentifierList;
  }

  /**
   * Gets list of all known, defined roles.
   *
   * @return list of defined roles
   */
  public List<BitIdentifier> getDefinedAccessRolesList()
  {
    return this.definedAccessRolesIdentifierList;
  }

  /**
   * Gets list of rights.
   *
   * @return list of rights
   */
  public List<BitIdentifier> getAccessRightsList()
  {
    return this.accessRightsIdentifierList;
  }

  /**
   * Gets list of roles.
   *
   * @return list of roles
   */
  public List<BitIdentifier> getAccessRolesList()
  {
    return this.accessRolesIdentifierList;
  }

  /**
   * Checks access right of certificate holder authorization exists.
   *
   * @param accessRight access right to be checked
   * @return <code>true</code>, if access right present, otherwise <code>false</code>
   */
  public boolean existsRight(BitIdentifier accessRight)
  {
    return this.accessRightsIdentifierList.contains(accessRight);
  }

  /**
   * Checks role of certificate holder authorization.
   *
   * @param accessRole access role to be checked
   * @return <code>true</code>, if access role present, otherwise <code>false</code>
   */
  public boolean isRole(BitIdentifier accessRole)
  {
    return this.accessRolesIdentifierList.contains(accessRole);
  }

  @Override
  public boolean equals(Object object)
  {
    return super.equals(object);
  }

  @Override
  public int hashCode()
  {
    return super.hashCode();
  }
}
