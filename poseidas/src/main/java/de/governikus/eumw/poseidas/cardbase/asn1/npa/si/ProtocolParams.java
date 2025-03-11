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

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.asn1.ASN1Constants;
import de.governikus.eumw.poseidas.cardbase.asn1.AbstractASN1Encoder;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>ProtocolParams</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class ProtocolParams extends AbstractASN1Encoder
{

  public ProtocolParams() throws IOException
  {
    super(new byte[]{ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED, 0x00});
  }

  /**
   * Gets version.
   *
   * @return version
   * @throws IOException
   */
  public int getVersion() throws IOException
  {
    return super.getInt(SecurityInfosPath.PROTOCOL_PARAMS_VERSION);
  }

  /**
   * Gets key ID.
   *
   * @return key ID
   * @throws IOException
   */
  public int getKeyID() throws IOException
  {
    return super.getInt(SecurityInfosPath.PROTOCOL_PARAMS_KEYID);
  }

  /**
   * Gets the <code>authorizedOnly</code> flag.
   *
   * @return value of <code>authorizedOnly</code>
   * @throws IOException
   */
  public boolean getAuthorizedOnly() throws IOException
  {
    return super.getChildElementByPath(SecurityInfosPath.PROTOCOL_PARAMS_AUTHORIZEDONLY).getValue()[0] == (byte)0xff;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("\n-- ProtocolParams: \n---- version ");
    try
    {
      result.append(this.getVersion());
      result.append("\n---- keyID ");
      result.append(this.getKeyID());
      result.append("\n---- authorizedOnly ");
      result.append(this.getAuthorizedOnly());
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    return result.toString();
  }
}
