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
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.ByteUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;


/**
 * Implementation of ASN.1 structure for CertificateHolderAuthorizationTemplate (CHAT).
 * <p>
 * Notice: see details at TC-03110, version 2.02, appendix C.
 * </p>
 *
 * @see AccessRoleAndRights
 * @author Jens Wothe, jw@bos-bremen.de
 */
public class CertificateHolderAuthorizationTemplate extends AbstractASN1Encoder implements ASN1Encoder
{

  // access role and rights
  private AccessRoleAndRights accessRoleAndRights;

  /**
   * Default encoder constructor (created ASN.1 is not initialized internally, use {@link #decode(ASN1)} for
   * complete initialization).
   *
   * @see AbstractASN1Encoder#AbstractASN1Encoder()
   */
  public CertificateHolderAuthorizationTemplate()
  {
    super();
  }

  /**
   * Constructor.
   *
   * @param bytes bytes of complete CHAT, <code>null</code> or empty not permitted
   * @throws IOException if reading of stream fails
   * @throws IllegalArgumentException if bytes <code>null</code> or empty or if bytes contain structure not
   *           complying with CHAT structure.
   * @see ASN1#ASN1(byte[])
   */
  public CertificateHolderAuthorizationTemplate(byte[] bytes) throws IOException
  {
    super();
    this.decode(bytes);
  }

  /**
   * Constructor.
   *
   * @param oidAccessRoleAndRights OID of access role and rights, <code>null</code> not permitted, OID must be
   *          one of {@link AuthenticationTerminals#OID_AUTHENTICATION_TERMINALS},
   *          {@link SignatureTerminals#OID_SIGNATURE_TERMINAL} or
   *          {@link InspectionSystems#OID_INSPECTION_SYSTEMS}, others not valid
   * @param chatMatrix byte[]-array with access mask, <code>null</code> or empty array not permitted,
   *          according to Class byte[]-array with different length expected
   * @throws IllegalArgumentException if byte[]-array of chat matrix invalid (<code>null</code> or incorrect
   *           length), OID <code>null</code> or not valid
   * @throws IOException if processing bytes fails, some decoding uses {@link ASN1#ASN1(byte[])}
   * @throws UnsupportedOperationException if decoding from bytes not supported
   */
  public CertificateHolderAuthorizationTemplate(OID oidAccessRoleAndRights, byte[] chatMatrix)
    throws IOException
  {
    super();
    AssertUtil.notNull(oidAccessRoleAndRights, "OID");
    AssertUtil.notNullOrEmpty(chatMatrix, "chat matrix bytes");
    ASN1 resultRolesAndRights = new ASN1(CertificateHolderAuthorizationTemplatePath.HAT_ACCESS_ROLE_AND_RIGHTS.getTag()
                                                                                                              .toByteArray(),
                                         chatMatrix);
    byte[] value = ByteUtil.combine(oidAccessRoleAndRights.getEncoded(), resultRolesAndRights.getEncoded());
    ASN1 asn1 = new ASN1(CertificateHolderAuthorizationTemplatePath.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.getTag()
                                                                                                             .toByteArray(),
                         value);
    this.decode(asn1.getEncoded());
    this.update();
  }

  public CertificateHolderAuthorizationTemplate(ChatTerminalType type, Collection<CVCPermission> options)
    throws IOException
  {
    super();
    AssertUtil.notNull(options, "chat options");
    if (type != ChatTerminalType.AUTHENTICATION_TERMINAL)
    {
      throw new IllegalArgumentException("unknown type");
    }
    byte[] matrixBytes = new byte[type.byteMatrixCount];
    for ( CVCPermission o : options )
    {
      if (o.getTerminalType() != type)
      {
        throw new IllegalArgumentException("given options not matching type");
      }
      matrixBytes[o.getByteIndex()] = (byte)(matrixBytes[o.getByteIndex()] | o.getByteMask());
    }
    OID oid = ATConstants.OID_AUTHENTICATION_TERMINALS;
    ASN1 resultRolesAndRights = new ASN1(ASN1EidConstants.TAG_DISCRETIONARY_DATA, matrixBytes);
    byte[] value = ByteUtil.combine(oid.getEncoded(), resultRolesAndRights.getEncoded());
    ASN1 asn1 = new ASN1(ASN1EidConstants.TAG_CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE.toArray(), value);
    this.decode(asn1.getEncoded());
    this.update();
  }

  /** {@inheritDoc} */
  @Override
  protected void update()
  {
    try
    {
      OID oidChild = (OID)this.getChildElementByPath(CertificateHolderAuthorizationTemplatePath.HAT_OID);
      ASN1 accessRoleAndRightsChild = this.getChildElementByPath(CertificateHolderAuthorizationTemplatePath.HAT_ACCESS_ROLE_AND_RIGHTS);
      if (oidChild == null || accessRoleAndRightsChild == null)
      {
        throw new IllegalArgumentException("incompatible ASN.1 object");
      }

      if (oidChild.getOIDString().equals(AuthenticationTerminals.getOIDString()))
      {
        this.accessRoleAndRights = new AuthenticationTerminals(accessRoleAndRightsChild.getEncoded());
      }
      else
      {
        throw new IllegalArgumentException("not acceptable OID used, possible OID is "
                                           + AuthenticationTerminals.getOIDString()
                                           + " for AuthenticationTerminals");
      }
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("incompatible ASN.1 object", e);
    }
  }

  /**
   * Gets Access Role and Rights of Certificate Holder Authorization.
   *
   * @return access role and rights
   */
  public AccessRoleAndRights getAccessRoleAndRights()
  {
    return this.accessRoleAndRights;
  }

  /** {@inheritDoc} */
  @Override
  public String toString(boolean format)
  {
    return super.toString(format) + "\nAccessRoleAndRights: "
           + (this.accessRoleAndRights != null ? this.accessRoleAndRights.getClass().getName() : null);
  }

  public enum ChatTerminalType
  {
    NONE(0), AUTHENTICATION_TERMINAL(ATConstants.VALUE_BYTE_COUNT);

    private int byteMatrixCount = -1;

    private ChatTerminalType(int byteMatrixCount)
    {
      this.byteMatrixCount = byteMatrixCount;
    }

  }

  /**
   * get an array of all ChatOptions that are allowed by this CHAT
   *
   * @return an array.
   */
  public Set<CVCPermission> getAllRights()
  {
    Collection<CVCPermission> options = CVCPermission.getOptions(this.accessRoleAndRights instanceof AuthenticationTerminals
      ? ChatTerminalType.AUTHENTICATION_TERMINAL : ChatTerminalType.NONE);
    Set<CVCPermission> result = new HashSet<>();
    for ( CVCPermission chatOption : options )
    {
      if (areBitsSet(chatOption))
      {
        result.add(chatOption);
      }
    }
    return result;
  }

  /**
   * Checks if bits are set for the given <code>ChatOption</code>
   *
   * @param chatOption to check
   * @return true if bits are set, false if not
   */
  public boolean areBitsSet(CVCPermission chatOption)
  {
    return this.accessRoleAndRights.existsRight(chatOption.getAccessRightEnum());
  }

  /**
   * Checks if bits are set for the given <code>ChatOption</code>
   *
   * @param chatOption to check
   * @return true if bits are set, false if not
   */
  private boolean areBitsSet(BitIdentifier chatOption)
  {
    return this.accessRoleAndRights.existsRight(chatOption);
  }

  public boolean isReadDocumentType()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG1);
  }

  public boolean isReadIssuingState()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG2);
  }

  public boolean isReadDateOfExpiry()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG3);
  }

  public boolean isReadGivenNames()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG4);
  }

  public boolean isReadFamilyNames()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG5);
  }

  public boolean isReadNomDePlume()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG6);
  }

  public boolean isReadAcademicTitle()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG7);
  }

  public boolean isReadDateOfBirth()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG8);
  }

  public boolean isReadPlaceOfBirth()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG9);
  }

  public boolean isReadNationality()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG10);
  }

  public boolean isReadSex()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG11);
  }

  public boolean isReadOptionalDataR()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG12);
  }

  public boolean isReadBirthName()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG13);
  }

  public boolean isReadWrittenSignature()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG14);
  }

  public boolean isReadDateOfIssuance()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG15);
  }

  public boolean isReadRFU4()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG16);
  }

  public boolean isReadPlaceOfResidence()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG17);
  }

  public boolean isReadMunicipalityID()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG18);
  }

  public boolean isReadResidencePermitI()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG19);
  }

  public boolean isReadResidencePermitII()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG20);
  }

  public boolean isReadPhoneNumber()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG21);
  }

  public boolean isReadEmailAddress()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.READ_DG22);
  }

  public boolean isPSA()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.PSA);
  }

  public boolean isAuthenticateAgeVerification()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.AGE_VERIFICATION);
  }

  public boolean isAuthenticateMunicipalityIDVerification()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.MUNICIPALITY_ID_VERIFICATION);
  }

  public boolean isAccessRightInstallCertificate()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.INSTALL_CERTIFICATE);
  }

  public boolean isAccessRightInstallQualifiedCertificate()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.INSTALL_QUALIFIED_CERTIFICATE);
  }

  public boolean isAccessRightPINManagement()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.PIN_MANAGEMENT);
  }

  public boolean isAuthenticateCANAllowed()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.CAN_ALLOWED);
  }

  public boolean isAuthenticateRestrictedIdentification()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.RESTRICTED_IDENTIFICATION);
  }

  public boolean isAuthenticatePrivilegedTerminal()
  {
    return areBitsSet(AuthenticationTerminals.AccessRightEnum.PRIVILEGED_TERMINAL);
  }

  @Override
  public String toString()
  {
    StringBuilder stringBuilder = new StringBuilder();
    if (this.accessRoleAndRights instanceof AuthenticationTerminals)
    {
      stringBuilder.append(CVCPermission.AUT_READ_DG01.getDescription() + ": ")
                   .append(isReadDocumentType())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG02.getDescription() + ": ")
                   .append(isReadIssuingState())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG03.getDescription() + ": ")
                   .append(isReadDateOfExpiry())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG04.getDescription() + ": ")
                   .append(isReadGivenNames())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG05.getDescription() + ": ")
                   .append(isReadFamilyNames())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG06.getDescription() + ": ")
                   .append(isReadNomDePlume())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG07.getDescription() + ": ")
                   .append(isReadAcademicTitle())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG08.getDescription() + ": ")
                   .append(isReadDateOfBirth())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG09.getDescription() + ": ")
                   .append(isReadPlaceOfBirth())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG10.getDescription() + ": ")
                   .append(isReadNationality())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG11.getDescription() + ": ")
                   .append(isReadSex())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG12.getDescription() + ": ")
                   .append(isReadOptionalDataR())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG13.getDescription() + ": ")
                   .append(isReadBirthName())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG14.getDescription() + ": ")
                   .append(isReadWrittenSignature())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG15.getDescription() + ": ")
                   .append(isReadDateOfIssuance())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG16.getDescription() + ": ")
                   .append(isReadRFU4())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG17.getDescription() + ": ")
                   .append(isReadPlaceOfResidence())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG18.getDescription() + ": ")
                   .append(isReadMunicipalityID())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG19.getDescription() + ": ")
                   .append(isReadResidencePermitI())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG20.getDescription() + ": ")
                   .append(isReadResidencePermitII())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG21.getDescription() + ": ")
                   .append(isReadPhoneNumber())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_READ_DG22.getDescription() + ": ")
                   .append(isReadEmailAddress())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_AGE_VERIFICATION.getDescription() + ": ")
                   .append(isAuthenticateAgeVerification())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_MUNICIPALITY_ID_VERIFICATION.getDescription() + ": ")
                   .append(isAuthenticateMunicipalityIDVerification())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_INSTALL_PIN_MANAGEMENT.getDescription() + ": ")
                   .append(isAccessRightPINManagement())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_CAN_ALLOWED.getDescription() + ": ")
                   .append(isAuthenticateCANAllowed())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_RESTRICTED_IDENTIFICATION.getDescription() + ": ")
                   .append(isAuthenticateRestrictedIdentification())
                   .append("\n");
      stringBuilder.append(CVCPermission.AUT_PRIVILEGED_TERMINAL.getDescription() + ": ")
                   .append(isAuthenticatePrivilegedTerminal())
                   .append("\n");
    }
    else
    {
      throw new IllegalArgumentException("ChatTerminalType is 'NULL' or of unknown type.");
    }
    return stringBuilder.toString();
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
