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

import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>PrivilegedTerminalInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class PrivilegedTerminalInfo extends SecurityInfo
{

  /**
   * Inner {@link SecurityInfos} for privileged terminals.
   */
  private SecurityInfos privilegedTerminalInfos;

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link PrivilegedTerminalInfo}.
   * @throws IOException if reading bytes fails
   */
  public PrivilegedTerminalInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets {@link SecurityInfos} for privileged terminals.
   *
   * @return {@link SecurityInfos}
   */
  public SecurityInfos getPrivilegedTerminalInfos() throws IOException
  {
    if (this.privilegedTerminalInfos == null)
    {
      this.privilegedTerminalInfos = (SecurityInfos)super.getChildElementByPath(SecurityInfosPath.PRIVILEGED_TERMINAL_INFO_PT_INFOS);
    }
    return this.privilegedTerminalInfos;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("PrivilegedTerminalInfo: ");
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
      result.append("\n-- privilegedTerminalInfos ");
      result.append(this.getPrivilegedTerminalInfos());
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    return result.toString();
  }

  @Override
  protected void update()
  {
    this.privilegedTerminalInfos = null;
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
