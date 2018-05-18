/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa.si;

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


public abstract class PSInfo extends SecurityInfo
{

  PSInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets version.
   * 
   * @return version
   * @throws IOException
   */
  public final int getVersion() throws IOException
  {
    return super.getInt(SecurityInfosPath.PS_INFO_REQUIRED_DATA_VERSION);
  }

  /**
   * Gets ps1-AuthInfo.
   * 
   * @return ps1-AuthInfo
   * @throws IOException
   */
  public final int getPS1AuthInfoInt() throws IOException
  {
    return super.getInt(SecurityInfosPath.PS_INFO_REQUIRED_DATA_PS1_AUTH_INFO);
  }

  /**
   * Gets ps2-AuthInfo.
   * 
   * @return ps2-AuthInfo
   * @throws IOException
   */
  public final int getPS2AuthInfoInt() throws IOException
  {
    return super.getInt(SecurityInfosPath.PS_INFO_REQUIRED_DATA_PS2_AUTH_INFO);
  }

  /**
   * Gets key ID if applicable.
   * 
   * @return key ID, <code>null</code> if not present
   * @throws IOException
   */
  public final Integer getKeyID() throws IOException
  {
    return super.getInteger(SecurityInfosPath.PS_INFO_KEY_ID);
  }
}
