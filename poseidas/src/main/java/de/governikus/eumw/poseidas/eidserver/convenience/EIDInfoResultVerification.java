/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience;

import java.io.Serializable;


/**
 * This is a Verification result. This should only be returned in response to a age verification or community
 * id verification request.
 *
 * @author Hauke Mehrtens
 */
public class EIDInfoResultVerification implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;

  private final boolean result;

  EIDInfoResultVerification(boolean result)
  {
    this.result = result;
  }

  public boolean isVertificationResult()
  {
    return result;
  }

  @Override
  public int hashCode()
  {
    return this.result ? 1 : 0;
  }

  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (obj == null || getClass() != obj.getClass())
    {
      return false;
    }
    EIDInfoResultVerification other = (EIDInfoResultVerification)obj;
    if (result != other.result)
    {
      return false;
    }
    return true;
  }

  @Override
  public String toString()
  {
    return Boolean.toString(result);
  }

}
