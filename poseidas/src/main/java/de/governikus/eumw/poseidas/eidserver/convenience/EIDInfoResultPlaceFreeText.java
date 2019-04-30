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
 * This is a Free Text Place info in the GeneralPlace structure. This should only be returned in response to a
 * place requested.
 *
 * @author Hauke Mehrtens
 */
public class EIDInfoResultPlaceFreeText implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;

  private final String freeTextPlace;

  EIDInfoResultPlaceFreeText(String freeTextPlace)
  {
    this.freeTextPlace = freeTextPlace;
  }

  public String getFreeTextPlace()
  {
    return freeTextPlace;
  }

  @Override
  public String toString()
  {
    return freeTextPlace;
  }

  @Override
  public int hashCode()
  {
    return (freeTextPlace == null) ? 0 : freeTextPlace.hashCode();
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
    EIDInfoResultPlaceFreeText other = (EIDInfoResultPlaceFreeText)obj;
    if (freeTextPlace == null)
    {
      if (other.freeTextPlace != null)
      {
        return false;
      }
    }
    else if (!freeTextPlace.equals(other.freeTextPlace))
    {
      return false;
    }
    return true;
  }

}
