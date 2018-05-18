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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;


/**
 * Access role and rights for Inspection Systems used by {@link CertificateHolderAuthorizationTemplate}.
 * <p>
 * Notice: see details at TC-03110, version 2.02, appendix C 4.1.
 * </p>
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class InspectionSystems extends BaseAccessRoleAndRights
{



  /**
   * Enum of access roles for Inspection System used by {@link CertificateHolderAuthorizationTemplate}.
   * 
   * @author Jens Wothe, jw@bos-bremen.de
   */
  private enum AccessRoleEnum implements BitIdentifier
  {
    /**
     * Role CVCA.
     * 
     * @see AccessRoleAndRights#IDENTIFIER_CVCA
     */
    CVCA(AccessRoleAndRights.IDENTIFIER_CVCA),
    /**
     * Role DV (official domestic).
     * 
     * @see BaseAccessRoleAndRights#IDENTIFIER_DV_OFFICIAL_DOMESTIC
     */
    DV_OFFICIAL_DOMESTIC(BaseAccessRoleAndRights.IDENTIFIER_DV_OFFICIAL_DOMESTIC),
    /**
     * Role DV (official foreign).
     * 
     * @see BaseAccessRoleAndRights#IDENTIFIER_DV_OFFICIAL_FOREIGN
     */
    DV_OFFICIAL_FOREIGN(BaseAccessRoleAndRights.IDENTIFIER_DV_OFFICIAL_FOREIGN),
    /**
     * Role Inspection System.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte, byte)
     * @see ISConstants#ROLE_NAME_INSPECTION_SYSTEM
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see AccessRoleAndRights#ACCESS_ROLE_MASK
     * @see ISConstants#ROLE_MASK_INSPECTION_SYSTEM
     */
    INSPECTION_SYSTEM(new BitIdentifierImpl(ISConstants.ROLE_NAME_INSPECTION_SYSTEM, ACCESS_ROLE_BYTE_INDEX, ACCESS_ROLE_MASK, ISConstants.ROLE_MASK_INSPECTION_SYSTEM));

    // identifier
    private BitIdentifier bitIdentifier = null;

    /**
     * Constructor with identifier.
     * 
     * @param bitIdentifier identifier, <code>null</code> not permitted
     * @throws IllegalArgumentException if identifier <code>null</code>
     */
    private AccessRoleEnum(BitIdentifier bitIdentifier)
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

  /**
   * Enum of access rights for Inspection System used by {@link CertificateHolderAuthorizationTemplate}.
   * 
   * @author Jens Wothe, jw@bos-bremen.de
   */
  public enum AccessRightEnum implements BitIdentifier
  {
    /**
     * Right to access eID application.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ISConstants#ACCESS_RIGHT_NAME_READ_ACCESS_EID_APPLICATION
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see ISConstants#ACCESS_RIGHT_MASK_READ_EID_APPLICATION
     */
    READ_ACCESS_EID_APPLICATION(new BitIdentifierImpl(ISConstants.ACCESS_RIGHT_NAME_READ_ACCESS_EID_APPLICATION,
                                                      ACCESS_ROLE_BYTE_INDEX,
                                                      ISConstants.ACCESS_RIGHT_MASK_READ_EID_APPLICATION)),
    /**
     * Right to access ePassport application: DG4 (Iris).
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ISConstants#ACCESS_RIGHT_NAME_READ_ACCESS_EPASSPORT_DG4
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see ISConstants#ACCESS_RIGHT_MASK_READ_EPASSPORT_DG4
     */
    READ_ACCESS_EPASSPORT_DG4(new BitIdentifierImpl(ISConstants.ACCESS_RIGHT_NAME_READ_ACCESS_EPASSPORT_DG4,
                                                    ACCESS_ROLE_BYTE_INDEX,
                                                    ISConstants.ACCESS_RIGHT_MASK_READ_EPASSPORT_DG4)),
    /**
     * Right to access ePassport application: DG3 (Fingerprint).
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ISConstants#ACCESS_RIGHT_NAME_READ_ACCESS_EPASSPORT_DG3
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see ISConstants#ACCESS_RIGHT_MASK_READ_EPASSPORT_DG3
     */
    READ_ACCESS_EPASSPORT_DG3(new BitIdentifierImpl(ISConstants.ACCESS_RIGHT_NAME_READ_ACCESS_EPASSPORT_DG3,
                                                    ACCESS_ROLE_BYTE_INDEX,
                                                    ISConstants.ACCESS_RIGHT_MASK_READ_EPASSPORT_DG3));


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

  /**
   * Constant list of access roles.
   */
  private static final List<BitIdentifier> ACCESS_ROLES_LIST = Collections.unmodifiableList(Arrays.asList((BitIdentifier[])AccessRoleEnum.values()));

  /**
   * Constant list of access rights.
   */
  private static final List<BitIdentifier> ACCESS_RIGHTS_LIST = Collections.unmodifiableList(Arrays.asList((BitIdentifier[])AccessRightEnum.values()));

  /**
   * Gets OID for Inspection System.
   * 
   * @return OID
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_INSPECTION_SYSTEM
   */
  static String getOIDString()
  {
    return ISConstants.OID_ACCESS_ROLE_AND_RIGHTS_INSPECTION_SYSTEM;
  }

  /**
   * Constructor.
   * 
   * @param bytes bytes of ASN.1 object
   * @throws IOException if reading of stream fails
   * @see BaseAccessRoleAndRights#BaseAccessRoleAndRights(byte[], int, List, List)
   * @see #VALUE_BYTE_COUNT
   * @see #ACCESS_ROLES_LIST
   * @see #ACCESS_RIGHTS_LIST
   */
  InspectionSystems(byte[] bytes) throws IOException
  {
    super(bytes, ISConstants.VALUE_BYTE_COUNT, ACCESS_ROLES_LIST, ACCESS_RIGHTS_LIST);
  }

  /**
   * Is role CVCA.
   * 
   * @return <code>true</code>, if role is CVCA, otherwise <code>false</code>
   * @see AccessRoleEnum#CVCA
   * @see AccessRoleAndRights#getAccessRolesList()
   * @see List#contains(Object)
   */
  public boolean isCVCA()
  {
    return super.getAccessRolesList().contains(AccessRoleEnum.CVCA);
  }

  /**
   * Is role DV (official domestic).
   * 
   * @return <code>true</code>, if role is DV (official domestic), otherwise <code>false</code>
   * @see AccessRoleEnum#DV_OFFICIAL_DOMESTIC
   * @see AccessRoleAndRights#isRole(BitIdentifier)
   */
  public boolean isDVOfficialDomestic()
  {
    return super.isRole(AccessRoleEnum.DV_OFFICIAL_DOMESTIC);
  }

  /**
   * Is role DV (official foreign).
   * 
   * @return <code>true</code>, if role is DV (official foreign), otherwise <code>false</code>
   * @see AccessRoleEnum#DV_OFFICIAL_FOREIGN
   * @see AccessRoleAndRights#isRole(BitIdentifier)
   */
  public boolean isDVOfficialForeign()
  {
    return super.isRole(AccessRoleEnum.DV_OFFICIAL_FOREIGN);
  }

  /**
   * Is role Inspection System.
   * 
   * @return <code>true</code>, if role is Inspection System, otherwise <code>false</code>
   * @see AccessRoleEnum#INSPECTION_SYSTEM
   * @see AccessRoleAndRights#isRole(BitIdentifier)
   */
  public boolean isInspectionSystem()
  {
    return isCVCA() || super.isRole(AccessRoleEnum.INSPECTION_SYSTEM);
  }

  /** {@inheritDoc} */
  public OID getOID()
  {
    return ISConstants.OID_INSPECTION_SYSTEMS;
  }

}
