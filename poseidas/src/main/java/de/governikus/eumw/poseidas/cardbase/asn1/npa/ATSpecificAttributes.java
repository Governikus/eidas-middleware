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

import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHTS_LIST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_INDEX_ACCESS_TO_ALL_TERMINAL_SECTORS;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_INDEX_DELETE_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_INDEX_INCL_SPEC_ATTR;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_INDEX_READ_ATT_REQUEST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_INDEX_READ_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_INDEX_WRITE_ATT_REQUEST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_INDEX_WRITE_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_MASK_ACCESS_TO_ALL_TERMINAL_SECTORS;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_MASK_DELETE_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_MASK_INCL_SPEC_ATTR;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_MASK_READ_ATT_REQUEST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_MASK_READ_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_MASK_WRITE_ATT_REQUEST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_MASK_WRITE_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_NAME_ACCESS_TO_ALL_TERMINAL_SECTORS;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_NAME_DELETE_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_NAME_INCL_SPEC_ATTR;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_NAME_READ_ATT_REQUEST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_NAME_READ_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_NAME_WRITE_ATT_REQUEST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_RIGHT_NAME_WRITE_SPEC_ATT;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.ACCESS_ROLES_LIST;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.ATSpecificAttributesConstants.VALUE_BYTE_COUNT;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.CertificateHolderAuthorizationTemplate.ChatTerminalType;
import de.governikus.eumw.poseidas.cardbase.npa.CVCPermission;


public class ATSpecificAttributes extends BaseAccessRoleAndRights
{

  /**
   * This set contains the permissions which can also be in the CHAT. It is important that this set is always
   * kept up-to-date.
   */
  public static final Collection<CVCPermission> SPEC_DOUBLES;
  static
  {
    Collection<CVCPermission> temp = new HashSet<>();
    SPEC_DOUBLES = Collections.unmodifiableCollection(temp);
  }

  /**
   * This set contains the permissions which can also be in the CHAT. It is important that this set is always
   * kept up-to-date.
   */
  public static final Collection<CVCPermission> CHAT_DOUBLES;
  static
  {
    Collection<CVCPermission> temp = new HashSet<>();
    CHAT_DOUBLES = Collections.unmodifiableCollection(temp);
  }

  public ATSpecificAttributes(byte[] bytes) throws IOException
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

  public static ATSpecificAttributes constructFromCVCPermissions(Collection<CVCPermission> options,
                                                                 boolean pscIncludeSpecific,
                                                                 boolean accessAll) throws IOException
  {
    byte[] matrixBytes = new byte[VALUE_BYTE_COUNT];
    for ( CVCPermission o : options )
    {
      if (!(o.getAccessRightEnum() instanceof ATSpecificAttributes.AccessRightEnum))
      {
        continue;
      }
      matrixBytes[o.getByteIndex()] |= o.getByteMask();
    }
    if (options.contains(CVCPermission.AUT_SF_PSC) && pscIncludeSpecific)
    {
      matrixBytes[ATSpecificAttributes.AccessRightEnum.INCL_SPEC_ATTR.getByteIndex()] |= ATSpecificAttributes.AccessRightEnum.INCL_SPEC_ATTR.getByteMask();
    }
    if ((options.contains(CVCPermission.AUT_READ_SPEC_ATT) || options.contains(CVCPermission.AUT_DELETE_SPEC_ATT))
        && accessAll)
    {
      matrixBytes[ATSpecificAttributes.AccessRightEnum.ACCESS_TO_ALL_TERMINAL_SECTORS.getByteIndex()] |= ATSpecificAttributes.AccessRightEnum.ACCESS_TO_ALL_TERMINAL_SECTORS.getByteMask();
    }
    ASN1 asn1 = new ASN1(ASN1EidConstants.TAG_DISCRETIONARY_DATA, matrixBytes);
    return new ATSpecificAttributes(asn1.getEncoded());
  }

  public boolean isAuthenticateIncludeSpecificAttributesToPSC()
  {
    return this.existsRight(AccessRightEnum.INCL_SPEC_ATTR);
  }

  public boolean isAuthenticateAccessToAllTerminalSectors()
  {
    return this.existsRight(AccessRightEnum.ACCESS_TO_ALL_TERMINAL_SECTORS);
  }

  public boolean isAuthenticateDeleteSpecificAttributes()
  {
    return this.existsRight(AccessRightEnum.DELETE_SPEC_ATT);
  }

  public boolean isAuthenticateWriteSpecificAttributes()
  {
    return this.existsRight(AccessRightEnum.WRITE_SPEC_ATT);
  }

  public boolean isAuthenticateReadSpecificAttributes()
  {
    return this.existsRight(AccessRightEnum.READ_SPEC_ATT);
  }

  public boolean isAuthenticateWriteAttributeRequest()
  {
    return this.existsRight(AccessRightEnum.WRITE_ATT_REQUEST);
  }

  public boolean isAuthenticateReadAttributeRequest()
  {
    return this.existsRight(AccessRightEnum.READ_ATT_REQUEST);
  }

  /**
   * Enum of access rights for Authentication Terminal Special Functions.
   */
  public enum AccessRightEnum implements BitIdentifier
  {
    /**
     * Include Specific Attributes to PSC.
     */
    INCL_SPEC_ATTR(new BitIdentifierImpl(ACCESS_RIGHT_NAME_INCL_SPEC_ATTR, ACCESS_RIGHT_INDEX_INCL_SPEC_ATTR,
                                         ACCESS_RIGHT_MASK_INCL_SPEC_ATTR)),

    /**
     * Access to all Terminal Sectors.
     */
    ACCESS_TO_ALL_TERMINAL_SECTORS(new BitIdentifierImpl(ACCESS_RIGHT_NAME_ACCESS_TO_ALL_TERMINAL_SECTORS,
                                                         ACCESS_RIGHT_INDEX_ACCESS_TO_ALL_TERMINAL_SECTORS,
                                                         ACCESS_RIGHT_MASK_ACCESS_TO_ALL_TERMINAL_SECTORS)),

    /**
     * Delete Specific Attributes.
     */
    DELETE_SPEC_ATT(new BitIdentifierImpl(ACCESS_RIGHT_NAME_DELETE_SPEC_ATT,
                                          ACCESS_RIGHT_INDEX_DELETE_SPEC_ATT,
                                          ACCESS_RIGHT_MASK_DELETE_SPEC_ATT)),

    /**
     * Write Specific Attribute.
     */
    WRITE_SPEC_ATT(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_SPEC_ATT, ACCESS_RIGHT_INDEX_WRITE_SPEC_ATT,
                                         ACCESS_RIGHT_MASK_WRITE_SPEC_ATT)),

    /**
     * Read Specific Attribute.
     */
    READ_SPEC_ATT(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_SPEC_ATT, ACCESS_RIGHT_INDEX_READ_SPEC_ATT,
                                        ACCESS_RIGHT_MASK_READ_SPEC_ATT)),

    /**
     * Write Attribute Request.
     */
    WRITE_ATT_REQUEST(new BitIdentifierImpl(ACCESS_RIGHT_NAME_WRITE_ATT_REQUEST,
                                            ACCESS_RIGHT_INDEX_WRITE_ATT_REQUEST,
                                            ACCESS_RIGHT_MASK_WRITE_ATT_REQUEST)),

    /**
     * Read Attribute Request.
     */
    READ_ATT_REQUEST(new BitIdentifierImpl(ACCESS_RIGHT_NAME_READ_ATT_REQUEST,
                                           ACCESS_RIGHT_INDEX_READ_ATT_REQUEST,
                                           ACCESS_RIGHT_MASK_READ_ATT_REQUEST));


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
