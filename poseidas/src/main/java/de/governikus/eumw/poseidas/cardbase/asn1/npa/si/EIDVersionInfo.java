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
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>eIDVersionInfo</code structure in {@link EIDSecurityInfo}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class EIDVersionInfo extends AbstractASN1Encoder
{

  public EIDVersionInfo() throws IOException
  {
    super(new byte[]{ASN1Constants.UNIVERSAL_TAG_SEQUENCE_CONSTRUCTED, 0x00});
  }

  /**
   * Gets eID version.
   *
   * @return eID version
   * @throws IOException
   */
  public String getEIDVersion() throws IOException
  {
    return super.getString(SecurityInfosPath.EID_SECURITY_INFO_VERSION_EID);
  }

  /**
   * Gets unicode version.
   *
   * @return unicode version
   * @throws IOException
   */
  public String getUnicodeVersion() throws IOException
  {
    return super.getString(SecurityInfosPath.EID_SECURITY_INFO_VERSION_UNICODE);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("\n-- EIDVersionInfo: \n---- eIDVersion ");
    try
    {
      result.append(this.getEIDVersion());
      result.append("\n---- unicodeVersion ");
      result.append(this.getUnicodeVersion());
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    return result.toString();
  }
}
