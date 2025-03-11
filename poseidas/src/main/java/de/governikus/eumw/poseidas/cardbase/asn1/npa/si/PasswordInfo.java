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
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_PROTOCOL;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Integer;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>PasswordInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public final class PasswordInfo extends SecurityInfo
{

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link PACEInfo}.
   * @throws IOException if reading bytes fails
   */
  public PasswordInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets password ID.
   *
   * @return password ID
   * @throws IOException
   */
  public int getPwdID() throws IOException
  {
    return super.getInt(SecurityInfosPath.PASSWORD_INFO_REQUIRED_DATA_PWD_ID);
  }

  private Set<Integer> getPwdSet(SecurityInfosPath path) throws IOException
  {
    ASN1 a = super.getChildElementByPath(path);
    if (a == null)
    {
      return null;
    }
    Set<Integer> result = new HashSet<>();
    for ( ASN1 child : a.getChildElementList() )
    {
      result.add(new BigInteger(child.getValue()).intValue());
    }
    return result;
  }

  public Set<Integer> getResumingPwds() throws IOException
  {
    return this.getPwdSet(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_RESUMING_PWDS);
  }

  public Set<Integer> getResettingPwds() throws IOException
  {
    return this.getPwdSet(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_RESETTING_PWDS);
  }

  public Set<Integer> getChangingPwds() throws IOException
  {
    return this.getPwdSet(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_CHANGING_PWDS);
  }

  public PwdType getPwdType() throws IOException
  {
    ASN1Integer a = (ASN1Integer)super.getChildElementByPath(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_PWD_TYPE);
    if (a == null)
    {
      return null;
    }
    return PwdType.values()[a.getInteger()];
  }

  public Integer getMinLength() throws IOException
  {
    return super.getInteger(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_MIN_LENGTH);
  }

  public Integer getStoredLength() throws IOException
  {
    return super.getInteger(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_STORED_LENGTH);
  }

  public Integer getMaxLength() throws IOException
  {
    return super.getInteger(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_MAX_LENGTH);
  }

  public Character getPadChar() throws IOException
  {
    ASN1 a = super.getChildElementByPath(SecurityInfosPath.PASSWORD_INFO_OPTIONAL_DATA_PAD_CHAR);
    if (a == null)
    {
      return null;
    }
    return (char)a.getValue()[0];
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("\nPasswordInfo: ");
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    return result.toString();
  }

  public enum PwdType
  {
    BCD, ASCII, UTF8, HALF_NIBBLE_BCD, ISO9564_1
  }
}
