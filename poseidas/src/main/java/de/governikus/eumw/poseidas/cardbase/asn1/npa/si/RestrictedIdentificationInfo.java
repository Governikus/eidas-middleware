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
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_NOT_GIVEN;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_PROTOCOL;

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>RestrictedIdentificationInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class RestrictedIdentificationInfo extends SecurityInfo
{

  /**
   * Reference to the <code>params</code> child element.
   */
  private ProtocolParams params;

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link RestrictedIdentificationInfo}.
   * @throws IOException if reading bytes fails
   */
  public RestrictedIdentificationInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets maximum key length.
   *
   * @return maximum key length, <code>null</code> possible
   * @throws IOException
   */
  public Integer getMaxKeyLen() throws IOException
  {
    return super.getInteger(SecurityInfosPath.RESTRICTED_IDENTIFICATION_INFO_MAXKEYLEN);
  }

  /**
   * Gets the child element <code>params</code>.
   *
   * @return {@link ProtocolParams} instance containing <code>params</code>, <code>null</code> possible
   * @throws IOException if error in getting
   */
  public ProtocolParams getParams() throws IOException
  {
    if (this.params == null)
    {
      this.params = (ProtocolParams)super.getChildElementByPath(SecurityInfosPath.RESTRICTED_IDENTIFICATION_INFO_PARAMS);
    }
    return this.params;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("RestrictedIdentificationInfo: ");
    Integer maxKeyLen = null;
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
      result.append(this.getParams());
      maxKeyLen = this.getMaxKeyLen();
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    result.append("\n-- maxKeyLen ");
    result.append(maxKeyLen != null ? maxKeyLen : STRING_NOT_GIVEN);
    return result.toString();
  }

  @Override
  protected void update()
  {
    this.params = null;
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
