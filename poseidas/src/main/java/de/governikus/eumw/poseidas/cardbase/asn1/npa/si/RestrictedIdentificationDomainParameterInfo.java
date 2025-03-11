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
 * Implementation of the <code>RestrictedIdentificationDomainParameterInfo</code> structure in
 * {@link SecurityInfos}.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class RestrictedIdentificationDomainParameterInfo extends DomainParameterInfo
{

  /**
   * Constructor.
   *
   * @param bytes byte-array containing ASN.1 description of a
   *          {@link RestrictedIdentificationDomainParameterInfo}
   * @throws IOException if reading bytes fails
   */
  public RestrictedIdentificationDomainParameterInfo(byte[] bytes) throws IOException
  {
    super(bytes);
  }

  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    StringBuilder result = new StringBuilder();
    result.append("RestrictedIdentificationDomainParameterInfo: ");
    try
    {
      result.append(STRING_PROTOCOL);
      result.append(super.getProtocol());
      result.append(super.getDomainParameter());
    }
    catch (IOException e)
    {
      throw new IllegalStateException(MESSAGE_CAN_NOT_CONVERT_TO_STRING, e);
    }
    return result.toString();
  }

  @Override
  protected void loadDomainParameter() throws IOException
  {
    super.domainParameter = (AlgorithmIdentifier)super.getChildElementByPath(SecurityInfosPath.RESTRICTED_IDENTIFICATION_DOMAIN_PARAMETER_INFO_DOMAIN_PARAMETER);
  }
}
