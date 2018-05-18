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
 * Access role and rights for Signature Terminals used by {@link CertificateHolderAuthorizationTemplate}.
 * <p>
 * Notice: see details at TC-03110, version 2.02, appendix C 4.3.
 * </p>
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class SignatureTerminals extends AccessRoleAndRights
{


  /**
   * Enum of access roles for Signature Terminal used by {@link CertificateHolderAuthorizationTemplate}.
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
     * Role DV (Accreditation Body).
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte, byte)
     * @see SignatureTerminals#ACCESS_ROLE_MASK_DV_ACCREDITATION_BODY
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see AccessRoleAndRights#ACCESS_ROLE_MASK
     * @see STConstants#ACCESS_ROLE_NAME_DV_ACCREDITATION_BODY
     */
    DV_ACCREDITATION_BODY(new BitIdentifierImpl(STConstants.ACCESS_ROLE_NAME_DV_ACCREDITATION_BODY,
                                                AccessRoleAndRights.ACCESS_ROLE_BYTE_INDEX,
                                                AccessRoleAndRights.ACCESS_ROLE_MASK,
                                                STConstants.ACCESS_ROLE_MASK_DV_ACCREDITATION_BODY)),
    /**
     * Role DV (Certification Service Provider).
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte, byte)
     * @see STConstants#ACCESS_ROLE_MASK_DV_CERTIFICATION_SERVICE_PROVIDER
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see AccessRoleAndRights#ACCESS_ROLE_MASK
     * @see STConstants#ACCESS_ROLE_NAME_DV_CERTIFICATION_SERVICE_PROVIDER
     */
    DV_CERTIFICATION_SERVICE_PROVIDER(new BitIdentifierImpl(
                                                            STConstants.ACCESS_ROLE_NAME_DV_CERTIFICATION_SERVICE_PROVIDER,
                                                            AccessRoleAndRights.ACCESS_ROLE_BYTE_INDEX,
                                                            AccessRoleAndRights.ACCESS_ROLE_MASK,
                                                            STConstants.ACCESS_ROLE_MASK_DV_CERTIFICATION_SERVICE_PROVIDER)),
    /**
     * Role Signature Terminal.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte, byte)
     * @see STConstants#ACCESS_ROLE_MASK_SIGNATURE_TERMINAL
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see AccessRoleAndRights#ACCESS_ROLE_MASK
     * @see STConstants#ACCESS_ROLE_NAME_SIGNATURE_TERMINAL
     */
    SIGNATURE_TERMINAL(new BitIdentifierImpl(STConstants.ACCESS_ROLE_NAME_SIGNATURE_TERMINAL, AccessRoleAndRights.ACCESS_ROLE_BYTE_INDEX, AccessRoleAndRights.ACCESS_ROLE_MASK, STConstants.ACCESS_ROLE_MASK_SIGNATURE_TERMINAL));

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
   * Enum of access rights for Signature Terminal used by {@link CertificateHolderAuthorizationTemplate}.
   * 
   * @author Jens Wothe, jw@bos-bremen.de
   */
  public enum AccessRightEnum implements BitIdentifier
  {
    /**
     * Right eSign Generate Qualified Electronic Signature.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see STConstants#ACCESS_RIGHT_NAME_ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see STConstants#ACCESS_RIGHT_NAME_ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE
     */
    ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE(new BitIdentifierImpl(
                                                                        STConstants.ACCESS_RIGHT_NAME_ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE,
                                                                        ACCESS_ROLE_BYTE_INDEX,
                                                                        STConstants.ACCESS_RIGHT_MASK_ESIGN_GENERATE_QUALIFIED_ELECTRONIC_SIGNATURE)),
    /**
     * Right eSign Generate Electronic Signature.
     * 
     * @see BitIdentifierImpl#BitIdentifierImpl(String, int, byte)
     * @see STConstants#ACCESS_RIGHT_NAME_ESIGN_GENERATE_ELECTRONIC_SIGNATURE
     * @see AccessRoleAndRights#ACCESS_ROLE_BYTE_INDEX
     * @see STConstants#ACCESS_RIGHT_MASK_ESIGN_GENERATE_ELECTRONIC_SIGNATURE
     */
    ESIGN_GENERATE_ELECTRONIC_SIGNATURE(new BitIdentifierImpl(
                                                              STConstants.ACCESS_RIGHT_NAME_ESIGN_GENERATE_ELECTRONIC_SIGNATURE,
                                                              ACCESS_ROLE_BYTE_INDEX,
                                                              STConstants.ACCESS_RIGHT_MASK_ESIGN_GENERATE_ELECTRONIC_SIGNATURE));

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
   * Gets OID for Signature Terminal.
   * 
   * @return OID
   * @see #OID_ACCESS_ROLE_AND_RIGHTS_SIGNATURE_TERMINAL
   */
  static String getOIDString()
  {
    return STConstants.OID_ACCESS_ROLE_AND_RIGHTS_SIGNATURE_TERMINAL;
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
  SignatureTerminals(byte[] bytes) throws IOException
  {
    super(bytes, STConstants.VALUE_BYTE_COUNT, ACCESS_ROLES_LIST, ACCESS_RIGHTS_LIST);
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
   * Is role DV (Accreditation Body).
   * 
   * @return <code>true</code>, if role is DV (Accreditation Body), otherwise <code>false</code>
   * @see AccessRoleEnum#DV_ACCREDITATION_BODY
   * @see AccessRoleAndRights#getAccessRolesList()
   * @see List#contains(Object)
   */
  public boolean isDVAccreditationBody()
  {
    return super.getAccessRolesList().contains(AccessRoleEnum.DV_ACCREDITATION_BODY);
  }

  /**
   * Is role DV (Certification Service Provider).
   * 
   * @return <code>true</code>, if role is DV (Certification Service Provider), otherwise <code>false</code>
   * @see AccessRoleEnum#DV_CERTIFICATION_SERVICE_PROVIDER
   * @see AccessRoleAndRights#getAccessRolesList()
   * @see List#contains(Object)
   */
  public boolean isDVCertificationServiceProvider()
  {
    return super.getAccessRolesList().contains(AccessRoleEnum.DV_CERTIFICATION_SERVICE_PROVIDER);
  }

  /**
   * Is role Signature Terminal.
   * 
   * @return <code>true</code>, if role is Signature Terminal, otherwise <code>false</code>
   * @see AccessRoleEnum#SIGNATURE_TERMINAL
   * @see AccessRoleAndRights#getAccessRolesList()
   * @see List#contains(Object)
   */
  public boolean isSignatureTerminal()
  {
    return super.getAccessRolesList().contains(AccessRoleEnum.SIGNATURE_TERMINAL);
  }

  /** {@inheritDoc} */
  public OID getOID()
  {
    return STConstants.OID_SIGNATURE_TERMINAL;
  }

}
