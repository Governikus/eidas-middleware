/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa.si;

import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.MESSAGE_CAN_NOT_CONVERT_TO_STRING;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_KEY_ID;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_NOT_GIVEN;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_PROTOCOL;

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>ChipAuthenticationPublicKeyInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class ChipAuthenticationPublicKeyInfo extends SecurityInfo
{

  /**
   * Reference to the <code>chipAuthenticationPublicKey</code> child element.
   */
  private SubjectPublicKeyInfo chipAuthenticationPublicKey;

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link ChipAuthenticationPublicKeyInfo}.
   * @throws IOException if reading bytes fails
   */
  public ChipAuthenticationPublicKeyInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets the child element <code>chipAuthenticationPublicKey</code>.
   *
   * @return {@link SubjectPublicKeyInfo} instance containing <code>chipAuthenticationPublicKey</code>,
   *         <code>null</code> possible
   * @throws IOException if error in getting
   */
  public SubjectPublicKeyInfo getChipAuthenticationPublicKey() throws IOException
  {
    if (this.chipAuthenticationPublicKey == null)
    {
      this.chipAuthenticationPublicKey = (SubjectPublicKeyInfo)super.getChildElementByPath(SecurityInfosPath.CHIP_AUTHENTICATION_PUBLIC_KEY_INFO_CHIP_AUTHENTICATION_PUBLIC_KEY);
    }
    return this.chipAuthenticationPublicKey;
  }

  /**
   * Gets key ID if applicable.
   *
   * @return key ID, <code>null</code> if not present
   * @throws IOException
   */
  public Integer getKeyID() throws IOException
  {
    return super.getInteger(SecurityInfosPath.CHIP_AUTHENTICATION_PUBLIC_KEY_INFO_KEY_ID);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("ChipAuthenticationPublicKeyInfo: ");
    Integer keyID = null;
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
      result.append(this.getChipAuthenticationPublicKey());
      keyID = this.getKeyID();
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    result.append(STRING_KEY_ID);
    result.append(keyID != null ? keyID : STRING_NOT_GIVEN);
    return result.toString();
  }

  @Override
  protected void update()
  {
    this.chipAuthenticationPublicKey = null;
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
