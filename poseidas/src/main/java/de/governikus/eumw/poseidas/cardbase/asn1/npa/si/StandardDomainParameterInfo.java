/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.asn1.npa.si;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;


/**
 * Class for a standard set of domain parameter infos referenced by an ID.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class StandardDomainParameterInfo implements GeneralDomainParameterInfo
{

  /**
   * ID of domain parameters.
   */
  private final Integer dpiID;

  /**
   * Constructor.
   *
   * @param dpiID ID of domain parameters
   * @throws IllegalArgumentException if given ID <code>null</code> or having unknown value
   */
  public StandardDomainParameterInfo(Integer dpiID)
  {
    AssertUtil.notNull(dpiID, "domain parameter ID");
    if (dpiID < MIN_DOMAIN_PARAMETER_ID || dpiID > MAX_DOMAIN_PARAMETER_ID)
    {
      throw new IllegalArgumentException("unknown domain parameter ID");
    }
    this.dpiID = dpiID;
  }

  /**
   * Gets domain parameter ID.
   *
   * @return domain parameter ID
   */
  public Integer getdpiID()
  {
    return this.dpiID;
  }
}
