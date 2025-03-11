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
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_PARAMETER_ID;
import static de.governikus.eumw.poseidas.cardbase.asn1.npa.si.SecurityInfoConstants.STRING_PROTOCOL;

import java.io.IOException;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfosPath;


/**
 * Implementation of the <code>PACEDomainParameterInfo</code> structure in {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class PACEDomainParameterInfo extends DomainParameterInfo
{

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a {@link PACEDomainParameterInfo}.
   * @throws IOException if reading bytes fails
   */
  public PACEDomainParameterInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /**
   * Gets parameter ID if applicable.
   *
   * @return parameter ID, <code>null</code> if not present
   * @throws IOException
   */
  public Integer getParameterID() throws IOException
  {
    return super.getInteger(SecurityInfosPath.PACE_DOMAIN_PARAMETER_INFO_PARAMETER_ID);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("PACEDomainParameterInfo: ");
    Integer parameterID = null;
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
      result.append(super.getDomainParameter());
      parameterID = this.getParameterID();
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    result.append(STRING_PARAMETER_ID);
    result.append(parameterID != null ? parameterID : STRING_NOT_GIVEN);
    return result.toString();
  }

  @Override
  protected void loadDomainParameter() throws IOException
  {
    super.domainParameter = (AlgorithmIdentifier)super.getChildElementByPath(SecurityInfosPath.PACE_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER);
  }
}
