/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.ri;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.RestrictedIdentificationInfo;
import de.governikus.eumw.poseidas.cardserver.eac.Parameter;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionParameter;


/**
 * Implementation of RestrictedIdentification input parameter.
 * 
 * @see RestrictedIdentification
 * @see Connector#execute(Parameter)
 * @see RestrictedIdentificationResult
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class RestrictedIdentificationParameter implements FunctionParameter
{

  /**
   * {@link RestrictedIdentificationInfo} to use.
   */
  private RestrictedIdentificationInfo riInfo = null;

  /**
   * First sector public key.
   */
  private byte[] firstKey = null;

  /**
   * Second sector public key.
   */
  private byte[] secondKey = null;


  /**
   * Constructor.
   * 
   * @param riInfo {@link RestrictedIdentificationInfo}
   * @param firstKey
   * @param secondKey
   * @throws IllegalArgumentException
   */
  public RestrictedIdentificationParameter(RestrictedIdentificationInfo riInfo,
                                           byte[] firstKey,
                                           byte[] secondKey)
  {
    AssertUtil.notNull(riInfo, "RestrictedIdentificationInfo");
    if ((firstKey == null || firstKey.length == 0) && (secondKey == null || secondKey.length == 0))
    {
      throw new IllegalArgumentException("at least one of the two keys must contain something");
    }
    this.riInfo = riInfo;
    this.firstKey = firstKey;
    this.secondKey = secondKey;
  }

  /**
   * Gets {@link RestrictedIdentificationInfo}.
   * 
   * @return {@link RestrictedIdentificationInfo}
   */
  public RestrictedIdentificationInfo getRiInfo()
  {
    return riInfo;
  }

  /**
   * Gets first key.
   * 
   * @return first key
   */
  public byte[] getFirstKey()
  {
    return this.firstKey;
  }

  /**
   * Gets second key.
   * 
   * @return second key
   */
  public byte[] getSecondKey()
  {
    return this.secondKey;
  }
}
