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


public class PSPublicKeyInfo extends SecurityInfo
{

  private SubjectPublicKeyInfo pSPublicKey = null;


  public PSPublicKeyInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  public SubjectPublicKeyInfo getpSPublicKey() throws IOException
  {
    if (this.pSPublicKey == null)
    {
      this.pSPublicKey = (SubjectPublicKeyInfo)super.getChildElementByPath(SecurityInfosPath.PS_PUBLIC_KEY_INFO_REQ_DATA_PS_PK);
    }
    return this.pSPublicKey;
  }

  /**
   * Gets pSParameterID if applicable.
   * 
   * @return pSParameterID, <code>null</code> if not present
   * @throws IOException
   */
  public Integer getPSParameterID() throws IOException
  {
    return super.getInteger(SecurityInfosPath.PS_PUBLIC_KEY_INFO_OPT_DATA_PS_PARAM_ID);
  }

  /**
   * Gets key ID if applicable.
   * 
   * @return key ID, <code>null</code> if not present
   * @throws IOException
   */
  public Integer getKeyID() throws IOException
  {
    return super.getInteger(SecurityInfosPath.PS_PUBLIC_KEY_INFO_OPT_DATA_KEY_ID);
  }

  @Override
  protected void update()
  {
    this.pSPublicKey = null;
  }
}
