/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.functions.ri;

import de.governikus.eumw.poseidas.cardserver.eac.AbstractResult;
import de.governikus.eumw.poseidas.cardserver.eac.functions.FunctionResult;


/**
 * Implementation of RestrictedIdentification output parameter.
 *
 * @see RestrictedIdentificationParameter
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class RestrictedIdentificationResult extends AbstractResult<byte[]> implements FunctionResult<byte[]>
{

  /**
   * The ID derived from first key.
   */
  private byte[] firstID = null;

  /**
   * The ID derived from second key.
   */
  private byte[] secondID = null;

  /**
   * Constructor.
   */
  public RestrictedIdentificationResult()
  {
    super();
  }

  /**
   * Constructor.
   */
  RestrictedIdentificationResult(Throwable throwable)
  {
    super(throwable);
  }

  /**
   * Gets first ID.
   *
   * @return first ID, may be <code>null</code>
   */
  public byte[] getFirstID()
  {
    return this.firstID;
  }

  /**
   * Sets first ID.
   *
   * @param firstID first ID
   */
  public void setFirstID(byte[] firstID)
  {
    this.firstID = firstID;
  }

  /**
   * Gets second ID.
   *
   * @return second ID, may be <code>null</code>
   */
  public byte[] getSecondID()
  {
    return this.secondID;
  }

  /**
   * Sets second ID.
   *
   * @param secondID second ID
   */
  public void setSecondID(byte[] secondID)
  {
    this.secondID = secondID;
  }
}
