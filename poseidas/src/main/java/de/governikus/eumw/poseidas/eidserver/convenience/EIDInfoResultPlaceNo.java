/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
 * This is a No Place info in the GeneralPlace structure. This should only be returned in response to a place
 * requested.
 * 
 * @author Hauke Mehrtens
 */
public class EIDInfoResultPlaceNo implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;

  private final String noPlaceInfo;

  EIDInfoResultPlaceNo(String noPlaceInfo)
  {
    this.noPlaceInfo = noPlaceInfo;
  }

  public String getNoPlaceInfo()
  {
    return noPlaceInfo;
  }

  @Override
  public String toString()
  {
    return noPlaceInfo;
  }

  @Override
  public int hashCode()
  {
    return (noPlaceInfo == null) ? 0 : noPlaceInfo.hashCode();
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
    EIDInfoResultPlaceNo other = (EIDInfoResultPlaceNo)obj;
    if (noPlaceInfo == null)
    {
      if (other.noPlaceInfo != null)
      {
        return false;
      }
    }
    else if (!noPlaceInfo.equals(other.noPlaceInfo))
    {
      return false;
    }
    return true;
  }

}
