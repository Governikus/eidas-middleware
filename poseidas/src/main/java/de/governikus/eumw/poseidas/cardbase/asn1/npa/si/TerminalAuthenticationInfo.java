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
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_VERSION;

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.Hex;
import de.governikus.eumw.poseidas.cardbase.asn1.ASN1;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>TerminalAuthenticationInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class TerminalAuthenticationInfo extends SecurityInfo
{

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link TerminalAuthenticationInfo}.
   * @throws IOException if reading bytes fails
   */
  public TerminalAuthenticationInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets version.
   *
   * @return version
   * @throws IOException
   */
  public int getVersion() throws IOException
  {
    return super.getInt(SecurityInfosPath.TERMINAL_AUTHENTICATION_INFO_VERSION);
  }

  /**
   * Gets the child element <code>EFCVCA</code>.
   *
   * @return {@link ASN1} instance containing <code>EFCVCA</code>, <code>null</code> possible
   * @throws IOException if error in getting
   */
  public ASN1 getEFCVCA() throws IOException
  {
    return super.getChildElementByPath(SecurityInfosPath.TERMINAL_AUTHENTICATION_INFO_EFCVCA);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("TerminalAuthenticationInfo: ");
    ASN1 efCVCA = null;
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
      result.append(STRING_VERSION);
      result.append(this.getVersion());
      efCVCA = this.getEFCVCA();
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    result.append("\n-- efCVCA ");
    result.append(efCVCA != null ? Hex.hexify(efCVCA.getValue()) : STRING_NOT_GIVEN);
    return result.toString();
  }
}
