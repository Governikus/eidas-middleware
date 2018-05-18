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

import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHTS_LIST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_INDEX_AGE_VERIFICATION;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_INDEX_MUNICIPALITY_ID_VERIFICATION;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_INDEX_PSA;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_INDEX_PSC;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_INDEX_PSM;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_INDEX_RI;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_MASK_AGE_VERIFICATION;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_MASK_MUNICIPALITY_ID_VERIFICATION;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_MASK_PSA;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_MASK_PSC;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_MASK_PSM;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_MASK_RI;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_NAME_AGE_VERIFICATION;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_NAME_MUNICIPALITY_ID_VERIFICATION;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_NAME_PSA;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_NAME_PSC;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_NAME_PSM;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_RIGHT_NAME_RI;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.ACCESS_ROLES_LIST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecialConstants.VALUE_BYTE_COUNT;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate.ChatTerminalType;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;


public class ATSpecialFunctions extends BaseAccessRoleAndRights
{

  /**
   * This set contains the permissions which can also be in the CHAT. It is important that this set is always
   * kept up-to-date.
   */
  public static final Collection<CVCPermission> SF_DOUBLES;
  static
  {
    Collection<CVCPermission> temp = new HashSet<>();
    temp.add(CVCPermission.AUT_SF_RESTRICTED_IDENTIFICATION);
    temp.add(CVCPermission.AUT_SF_MUNICIPALITY_ID_VERIFICATION);
    temp.add(CVCPermission.AUT_SF_AGE_VERIFICATION);
    temp.add(CVCPermission.AUT_SF_PSA);
    SF_DOUBLES = Collections.unmodifiableCollection(temp);
  }

  /**
   * This set contains the permissions which can also be in the CHAT. It is important that this set is always
   * kept up-to-date.
   */
  public static final Collection<CVCPermission> CHAT_DOUBLES;
  static
  {
    Collection<CVCPermission> temp = new HashSet<>();
    temp.add(CVCPermission.AUT_RESTRICTED_IDENTIFICATION);
    temp.add(CVCPermission.AUT_MUNICIPALITY_ID_VERIFICATION);
    temp.add(CVCPermission.AUT_AGE_VERIFICATION);
    temp.add(CVCPermission.AUT_PSA);
    CHAT_DOUBLES = Collections.unmodifiableCollection(temp);
  }

  public ATSpecialFunctions(byte[] bytes) throws IOException
  {
    super(bytes, VALUE_BYTE_COUNT, ACCESS_ROLES_LIST, ACCESS_RIGHTS_LIST);
  }

  /**
   * Get an array of all access rights that are allowed by this instance.
   * 
   * @return an array.
   */
  public Set<CVCPermission> getAllRights()
  {
    Set<CVCPermission> options = CVCPermission.getOptions(ChatTerminalType.AUTHENTICATION_TERMINAL);
    Set<CVCPermission> result = new HashSet<>();
    for ( CVCPermission chatOption : options )
    {
      if (existsRight(chatOption.getAccessRightEnum()))
      {
        result.add(chatOption);
      }
    }
    return result;
  }

  public static ATSpecialFunctions constructFromCVCPermissions(Collection<CVCPermission> options)
    throws IOException
  {
    byte[] matrixBytes = new byte[VALUE_BYTE_COUNT];
    for ( CVCPermission o : options )
    {
      if (!(o.getAccessRightEnum() instanceof ATSpecialFunctions.AccessRightEnum))
      {
        continue;
      }
      matrixBytes[o.getByteIndex()] |= o.getByteMask();
    }
    ASN1 asn1 = new ASN1(ASN1EidConstants.TAG_DISCRETIONARY_DATA, matrixBytes);
    return new ATSpecialFunctions(asn1.getEncoded());
  }

  public boolean isAuthenticateAgeVerification()
  {
    return this.existsRight(AccessRightEnum.AGE_VERIFICATION);
  }

  public boolean isAuthenticateMunicipalityIDVerification()
  {
    return this.existsRight(AccessRightEnum.MUNICIPALITY_ID_VERIFICATION);
  }

  public boolean isAuthenticateRestrictedIdentification()
  {
    return this.existsRight(AccessRightEnum.RESTRICTED_IDENTIFICATION);
  }

  public boolean isPerformPseudonymousSignatureAuthentication()
  {
    return this.existsRight(AccessRightEnum.PSA);
  }

  public boolean isPerformPseudonymousSignatureCredentials()
  {
    return this.existsRight(AccessRightEnum.PSC);
  }

  public boolean isPerformPseudonymousSignatureMessage()
  {
    return this.existsRight(AccessRightEnum.PSM);
  }

  /**
   * Enum of access rights for Authentication Terminal Special Functions.
   */
  public enum AccessRightEnum implements BitIdentifier
  {
    /**
     * PSC.
     */
    PSC(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSC, ACCESS_RIGHT_INDEX_PSC, ACCESS_RIGHT_MASK_PSC)),

    /**
     * PSM.
     */
    PSM(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSM, ACCESS_RIGHT_INDEX_PSM, ACCESS_RIGHT_MASK_PSM)),

    /**
     * PSA.
     */
    PSA(new BitIdentifierImpl(ACCESS_RIGHT_NAME_PSA, ACCESS_RIGHT_INDEX_PSA, ACCESS_RIGHT_MASK_PSA)),

    /**
     * Restricted Identification.
     */
    RESTRICTED_IDENTIFICATION(new BitIdentifierImpl(ACCESS_RIGHT_NAME_RI, ACCESS_RIGHT_INDEX_RI,
                                                    ACCESS_RIGHT_MASK_RI)),

    /**
     * Municipality ID Verification.
     */
    MUNICIPALITY_ID_VERIFICATION(new BitIdentifierImpl(ACCESS_RIGHT_NAME_MUNICIPALITY_ID_VERIFICATION,
                                                       ACCESS_RIGHT_INDEX_MUNICIPALITY_ID_VERIFICATION,
                                                       ACCESS_RIGHT_MASK_MUNICIPALITY_ID_VERIFICATION)),

    /**
     * Age Verification.
     */
    AGE_VERIFICATION(new BitIdentifierImpl(ACCESS_RIGHT_NAME_AGE_VERIFICATION,
                                           ACCESS_RIGHT_INDEX_AGE_VERIFICATION,
                                           ACCESS_RIGHT_MASK_AGE_VERIFICATION)), ;

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
}
