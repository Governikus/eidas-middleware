/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
 * This is a String result. This should only be returned in response reading out String attribute.
 *
 * @author Hauke Mehrtens
 */
public class EIDInfoResultString implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;

  private final String result;

  public EIDInfoResultString(String result)
  {
    this.result = result;
  }

  @Override
  public String toString()
  {
    return result;
  }

  public String getResult()
  {
    return result;
  }

  @Override
  public int hashCode()
  {
    return (result == null) ? 0 : result.hashCode();
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
    EIDInfoResultString other = (EIDInfoResultString)obj;
    if (result == null)
    {
      if (other.result != null)
      {
        return false;
      }
    }
    else if (!result.equals(other.result))
    {
      return false;
    }
    return true;
  }
}
