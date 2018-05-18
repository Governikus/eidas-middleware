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

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;


/**
 * Access role and rights for Authentication Terminals used by {@link CertificateHolderAuthorizationTemplate}.
 * <p>
 * Notice: see details at TC-03110, version 2.02, appendix C 4.2.
 * </p>
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class AuthenticationTerminals extends BaseAccessRoleAndRights
{

  /**
   * Enum of access roles for Authentication Terminal used by {@link CertificateHolderAuthorizationTemplate}.
   * 
   * @author Jens Wothe, jw@bos-bremen.de
   */
  public enum AccessRoleEnum implements BitIdentifier
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
     * Role Authentication Terminal.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte, byte)
     * @see ATConstants#ACCESS_ROLE_MASK_AUTHENTICATION_TERMINAL
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see AccessRoleAndRights#ACCESS_ROLE_MASK
     * @see ATConstants#ACCESS_ROLE_NAME_AUTHENTICATION_TERMINAL
     */
    AUTHENTICATION_TERMINAL(new BitIdentifierImpl(ATConstants.ACCESS_ROLE_NAME_AUTHENTICATION_TERMINAL,
                                                  AccessRoleAndRights.ACCESS_ROLE_BYTE_INDEX,
                                                  AccessRoleAndRights.ACCESS_ROLE_MASK,
                                                  ATConstants.ACCESS_ROLE_MASK_AUTHENTICATION_TERMINAL));

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
   * Enum of access rights for Authentication Terminal used by {@link CertificateHolderAuthorizationTemplate}.
   * 
   * @author Jens Wothe, jw@bos-bremen.de
   */
  public enum AccessRightEnum implements BitIdentifier
  {
    /**
     * Right Write DG17.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_WRITE_DG17
     * @see ATConstants#ACCESS_RIGHT_INDEX_WRITE_DG17
     * @see ATConstants#ACCESS_RIGHT_MASK_WRITE_DG17
     */
    WRITE_DG17(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_WRITE_DG17, ATConstants.ACCESS_RIGHT_INDEX_WRITE_DG17, ATConstants.ACCESS_RIGHT_MASK_WRITE_DG17)),
    /**
     * Right Write DG18.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_WRITE_DG18
     * @see ATConstants#ACCESS_RIGHT_INDEX_WRITE_DG18
     * @see ATConstants#ACCESS_RIGHT_MASK_WRITE_DG18
     */
    WRITE_DG18(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_WRITE_DG18, ATConstants.ACCESS_RIGHT_INDEX_WRITE_DG18, ATConstants.ACCESS_RIGHT_MASK_WRITE_DG18)),
    /**
     * Right Write DG19.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_WRITE_DG19
     * @see ATConstants#ACCESS_RIGHT_INDEX_WRITE_DG19
     * @see ATConstants#ACCESS_RIGHT_MASK_WRITE_DG19
     */
    WRITE_DG19(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_WRITE_DG19, ATConstants.ACCESS_RIGHT_INDEX_WRITE_DG19, ATConstants.ACCESS_RIGHT_MASK_WRITE_DG19)),
    /**
     * Right Write DG20.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_WRITE_DG20
     * @see ATConstants#ACCESS_RIGHT_INDEX_WRITE_DG20
     * @see ATConstants#ACCESS_RIGHT_MASK_WRITE_DG20
     */
    WRITE_DG20(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_WRITE_DG20, ATConstants.ACCESS_RIGHT_INDEX_WRITE_DG20, ATConstants.ACCESS_RIGHT_MASK_WRITE_DG20)),
    /**
     * Right Write DG21.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_WRITE_DG21
     * @see ATConstants#ACCESS_RIGHT_INDEX_WRITE_DG21
     * @see ATConstants#ACCESS_RIGHT_MASK_WRITE_DG21
     */
    WRITE_DG21(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_WRITE_DG21, ATConstants.ACCESS_RIGHT_INDEX_WRITE_DG21, ATConstants.ACCESS_RIGHT_MASK_WRITE_DG21)),
    /**
     * Right Write DG22.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_WRITE_DG22
     * @see ATConstants#ACCESS_RIGHT_INDEX_WRITE_DG22
     * @see ATConstants#ACCESS_RIGHT_MASK_WRITE_DG22
     */
    WRITE_DG22(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_WRITE_DG22, ATConstants.ACCESS_RIGHT_INDEX_WRITE_DG22, ATConstants.ACCESS_RIGHT_MASK_WRITE_DG22)),
    /**
     * Right PSA.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_PSA
     * @see ATConstants#ACCESS_RIGHT_INDEX_PSA
     * @see ATConstants#ACCESS_RIGHT_MASK_PSA
     */
    PSA(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_PSA, ATConstants.ACCESS_RIGHT_INDEX_PSA, ATConstants.ACCESS_RIGHT_MASK_PSA)),
    /**
     * Right Read DG22.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG22
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG22
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG22
     */
    READ_DG22(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG22, ATConstants.ACCESS_RIGHT_INDEX_READ_DG22, ATConstants.ACCESS_RIGHT_MASK_READ_DG22)),
    /**
     * Right Read DG21.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG21
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG21
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG21
     */
    READ_DG21(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG21, ATConstants.ACCESS_RIGHT_INDEX_READ_DG21, ATConstants.ACCESS_RIGHT_MASK_READ_DG21)),
    /**
     * Right Read DG20.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG20
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG20
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG20
     */
    READ_DG20(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG20, ATConstants.ACCESS_RIGHT_INDEX_READ_DG20, ATConstants.ACCESS_RIGHT_MASK_READ_DG20)),
    /**
     * Right Read DG19.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG19
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG19
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG19
     */
    READ_DG19(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG19, ATConstants.ACCESS_RIGHT_INDEX_READ_DG19, ATConstants.ACCESS_RIGHT_MASK_READ_DG19)),
    /**
     * Right Read DG18.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG18
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG18
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG18
     */
    READ_DG18(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG18, ATConstants.ACCESS_RIGHT_INDEX_READ_DG18, ATConstants.ACCESS_RIGHT_MASK_READ_DG18)),
    /**
     * Right Read DG17.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG17
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG17
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG17
     */
    READ_DG17(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG17, ATConstants.ACCESS_RIGHT_INDEX_READ_DG17, ATConstants.ACCESS_RIGHT_MASK_READ_DG17)),
    /**
     * Right Read DG16.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG16
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG16
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG16
     */
    READ_DG16(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG16, ATConstants.ACCESS_RIGHT_INDEX_READ_DG16, ATConstants.ACCESS_RIGHT_MASK_READ_DG16)),
    /**
     * Right Read DG15.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG15
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG15
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG15
     */
    READ_DG15(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG15, ATConstants.ACCESS_RIGHT_INDEX_READ_DG15, ATConstants.ACCESS_RIGHT_MASK_READ_DG15)),
    /**
     * Right Read DG14.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG14
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG14
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG14
     */
    READ_DG14(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG14, ATConstants.ACCESS_RIGHT_INDEX_READ_DG14, ATConstants.ACCESS_RIGHT_MASK_READ_DG14)),
    /**
     * Right Read DG13.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG13
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG13
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG13
     */
    READ_DG13(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG13, ATConstants.ACCESS_RIGHT_INDEX_READ_DG13, ATConstants.ACCESS_RIGHT_MASK_READ_DG13)),
    /**
     * Right Read DG12.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG12
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG12
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG12
     */
    READ_DG12(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG12, ATConstants.ACCESS_RIGHT_INDEX_READ_DG12, ATConstants.ACCESS_RIGHT_MASK_READ_DG12)),
    /**
     * Right Read DG11.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG11
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG11
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG11
     */
    READ_DG11(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG11, ATConstants.ACCESS_RIGHT_INDEX_READ_DG11, ATConstants.ACCESS_RIGHT_MASK_READ_DG11)),
    /**
     * Right Read DG10.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG10
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG10
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG10
     */
    READ_DG10(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG10, ATConstants.ACCESS_RIGHT_INDEX_READ_DG10, ATConstants.ACCESS_RIGHT_MASK_READ_DG10)),
    /**
     * Right Read DG9.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG9
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG9
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG9
     */
    READ_DG9(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG9, ATConstants.ACCESS_RIGHT_INDEX_READ_DG9, ATConstants.ACCESS_RIGHT_MASK_READ_DG9)),
    /**
     * Right Read DG8.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG8
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG8
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG8
     */
    READ_DG8(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG8, ATConstants.ACCESS_RIGHT_INDEX_READ_DG8, ATConstants.ACCESS_RIGHT_MASK_READ_DG8)),
    /**
     * Right Read DG7.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG7
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG7
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG7
     */
    READ_DG7(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG7, ATConstants.ACCESS_RIGHT_INDEX_READ_DG7, ATConstants.ACCESS_RIGHT_MASK_READ_DG7)),
    /**
     * Right Read DG6.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG6
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG6
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG6
     */
    READ_DG6(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG6, ATConstants.ACCESS_RIGHT_INDEX_READ_DG6, ATConstants.ACCESS_RIGHT_MASK_READ_DG6)),
    /**
     * Right Read DG5.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG5
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG5
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG5
     */
    READ_DG5(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG5, ATConstants.ACCESS_RIGHT_INDEX_READ_DG5, ATConstants.ACCESS_RIGHT_MASK_READ_DG5)),
    /**
     * Right Read DG4.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG4
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG4
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG4
     */
    READ_DG4(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG4, ATConstants.ACCESS_RIGHT_INDEX_READ_DG4, ATConstants.ACCESS_RIGHT_MASK_READ_DG4)),
    /**
     * Right Read DG3.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG3
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG3
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG3
     */
    READ_DG3(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG3, ATConstants.ACCESS_RIGHT_INDEX_READ_DG3, ATConstants.ACCESS_RIGHT_MASK_READ_DG3)),
    /**
     * Right Read DG2.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG2
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG2
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG2
     */
    READ_DG2(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG2, ATConstants.ACCESS_RIGHT_INDEX_READ_DG2, ATConstants.ACCESS_RIGHT_MASK_READ_DG2)),
    /**
     * Right Read DG1.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_READ_DG1
     * @see ATConstants#ACCESS_RIGHT_INDEX_READ_DG1
     * @see ATConstants#ACCESS_RIGHT_MASK_READ_DG1
     */
    READ_DG1(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_READ_DG1, ATConstants.ACCESS_RIGHT_INDEX_READ_DG1, ATConstants.ACCESS_RIGHT_MASK_READ_DG1)),
    /**
     * Right Install Qualified Certificate.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_INSTALL_QUALIFIED_CERTIFICATE
     * @see ATConstants#ACCESS_RIGHT_INDEX_INSTALL_QUALIFIED_CERTIFICATE
     * @see ATConstants#ACCESS_RIGHT_MASK_INSTALL_QUALIFIED_CERTIFICATE
     */
    INSTALL_QUALIFIED_CERTIFICATE(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_INSTALL_QUALIFIED_CERTIFICATE, ATConstants.ACCESS_RIGHT_INDEX_INSTALL_QUALIFIED_CERTIFICATE, ATConstants.ACCESS_RIGHT_MASK_INSTALL_QUALIFIED_CERTIFICATE)),
    /**
     * Right Install Certificate.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_INSTALL_CERTIFICATE
     * @see ATConstants#ACCESS_RIGHT_INDEX_INSTALL_CERTIFICATE
     * @see ATConstants#ACCESS_RIGHT_MASK_INSTALL_CERTIFICATE
     */
    INSTALL_CERTIFICATE(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_INSTALL_CERTIFICATE, ATConstants.ACCESS_RIGHT_INDEX_INSTALL_CERTIFICATE, ATConstants.ACCESS_RIGHT_MASK_INSTALL_CERTIFICATE)),
    /**
     * Right PIN Management.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_PIN_MANAGEMENT
     * @see ATConstants#ACCESS_RIGHT_INDEX_PIN_MANAGEMENT
     * @see ATConstants#ACCESS_RIGHT_MASK_PIN_MANAGEMENT
     */
    PIN_MANAGEMENT(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_PIN_MANAGEMENT, ATConstants.ACCESS_RIGHT_INDEX_PIN_MANAGEMENT, ATConstants.ACCESS_RIGHT_MASK_PIN_MANAGEMENT)),
    /**
     * Right CAN allowed.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_CAN_ALLOWED
     * @see ATConstants#ACCESS_RIGHT_INDEX_CAN_ALLOWED
     * @see ATConstants#ACCESS_RIGHT_MASK_CAN_ALLOWED
     */
    CAN_ALLOWED(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_CAN_ALLOWED, ATConstants.ACCESS_RIGHT_INDEX_CAN_ALLOWED, ATConstants.ACCESS_RIGHT_MASK_CAN_ALLOWED)),
    /**
     * Right Privileged Terminal.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_PRIVILEGED_TERMINAL
     * @see ATConstants#ACCESS_RIGHT_INDEX_PRIVILEGED_TERMINAL
     * @see ATConstants#ACCESS_RIGHT_MASK_PRIVILEGED_TERMINAL
     */
    PRIVILEGED_TERMINAL(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_PRIVILEGED_TERMINAL, ATConstants.ACCESS_RIGHT_INDEX_PRIVILEGED_TERMINAL, ATConstants.ACCESS_RIGHT_MASK_PRIVILEGED_TERMINAL)),
    /**
     * Right Restricted Identification.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_RESTRICTED_IDENTIFICATION
     * @see ATConstants#ACCESS_RIGHT_INDEX_RESTRICTED_IDENTIFICATION
     * @see ATConstants#ACCESS_RIGHT_MASK_RESTRICTED_IDENTIFICATION
     */
    RESTRICTED_IDENTIFICATION(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_RESTRICTED_IDENTIFICATION, ATConstants.ACCESS_RIGHT_INDEX_RESTRICTED_IDENTIFICATION, ATConstants.ACCESS_RIGHT_MASK_RESTRICTED_IDENTIFICATION)),
    /**
     * Right Municipality ID Verification.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_MUNICIPALITY_ID_VERIFICATION
     * @see ATConstants#ACCESS_RIGHT_INDEX_MUNICIPALITY_ID_VERIFICATION
     * @see ATConstants#ACCESS_RIGHT_MASK_MUNICIPALITY_ID_VERIFICATION
     */
    MUNICIPALITY_ID_VERIFICATION(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_MUNICIPALITY_ID_VERIFICATION, ATConstants.ACCESS_RIGHT_INDEX_MUNICIPALITY_ID_VERIFICATION, ATConstants.ACCESS_RIGHT_MASK_MUNICIPALITY_ID_VERIFICATION)),
    /**
     * Right Age Verification.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see ATConstants#ACCESS_RIGHT_NAME_AGE_VERIFICATION
     * @see ATConstants#ACCESS_RIGHT_INDEX_AGE_VERIFICATION
     * @see ATConstants#ACCESS_RIGHT_MASK_AGE_VERIFICATION
     */
    AGE_VERIFICATION(new BitIdentifierImpl(ATConstants.ACCESS_RIGHT_NAME_AGE_VERIFICATION, ATConstants.ACCESS_RIGHT_INDEX_AGE_VERIFICATION, ATConstants.ACCESS_RIGHT_MASK_AGE_VERIFICATION));

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
   * Gets OID for Authentication Terminal.
   * 
   * @return OID
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL
   */
  static String getOIDString()
  {
    return ATConstants.OID_ACCESS_ROLE_AND_RIGHTS_AUTHENTICATION_TERMINAL;
  }

  /**
   * Constructor.
   * 
   * @param bytes bytes of ASN.1 object
   * @throws IOException if reading of stream fails
   * @see BaseAccessRoleAndRights#BaseAccessRoleAndRights(byte[], int, java.util.List, java.util.List)
   * @see #VALUE_BYTE_COUNT
   * @see #ACCESS_ROLES_LIST
   * @see #ACCESS_RIGHTS_LIST
   */
  AuthenticationTerminals(byte[] bytes) throws IOException
  {
    super(bytes, ATConstants.VALUE_BYTE_COUNT, ATConstants.ACCESS_ROLES_LIST, ATConstants.ACCESS_RIGHTS_LIST);
  }

  /**
   * Is role CVCA.
   * 
   * @return <code>true</code>, if role is CVCA, otherwise <code>false</code>
   * @see AccessRoleEnum#CVCA
   * @see AccessRoleAndRights#isRole(BitIdentifier)
   */
  public boolean isCVCA()
  {
    return super.isRole(AccessRoleEnum.CVCA);
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
   * Is role Authentication Terminal.
   * 
   * @return <code>true</code>, if role is Authentication Terminal, otherwise <code>false</code>
   * @see AccessRoleEnum#AUTHENTICATION_TERMINAL
   * @see AccessRoleAndRights#isRole(BitIdentifier)
   */
  public boolean isAuthenticationTerminal()
  {
    return isCVCA() || super.isRole(AccessRoleEnum.AUTHENTICATION_TERMINAL);
  }
}
