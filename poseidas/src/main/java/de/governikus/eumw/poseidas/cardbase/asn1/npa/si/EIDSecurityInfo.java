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

import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>eIDSecurityInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class EIDSecurityInfo extends SecurityInfo
{

  /**
   * <code>eIDSecurityObject</code> element.
   */
  private EIDSecurityObject eidSecurityObject;

  /**
   * Optional <code>eIDVersionInfo</code> element.
   */
  private EIDVersionInfo eidVersionInfo;

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of an {@link EIDSecurityInfo}.
   * @throws IOException if reading bytes fails
   */
  public EIDSecurityInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets the child element <code>eIDSecurityObject</code>.
   *
   * @return {@link EIDSecurityObject} instance
   * @throws IOException if error in getting
   */
  public EIDSecurityObject getEIDSecurityObject() throws IOException
  {
    if (this.eidSecurityObject == null)
    {
      this.eidSecurityObject = (EIDSecurityObject)super.getChildElementByPath(SecurityInfosPath.EID_SECURITY_INFO_OBJECT);
    }
    return this.eidSecurityObject;
  }

  /**
   * Gets the child element <code>eIDVersionInfo</code>.
   *
   * @return {@link EIDVersionInfo} instance, may be <code>null</code>
   * @throws IOException if error in getting
   */
  public EIDVersionInfo getEIDVersionInfo() throws IOException
  {
    if (this.eidVersionInfo == null)
    {
      this.eidVersionInfo = (EIDVersionInfo)super.getChildElementByPath(SecurityInfosPath.EID_SECURITY_INFO_VERSION);
    }
    return this.eidVersionInfo;
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("eIDSecurityInfo: ");
    EIDVersionInfo versionInfo = null;
    try
    {
      result.append(this.getEIDSecurityObject());
      versionInfo = this.getEIDVersionInfo();
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    result.append(versionInfo != null ? versionInfo : "");
    return result.toString();
  }

  @Override
  protected void update()
  {
    this.eidSecurityObject = null;
    this.eidVersionInfo = null;
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
