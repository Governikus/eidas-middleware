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
 * This is a Structured Place info in the GeneralPlace structure. This should only be returned in response to
 * a place requested.
 * 
 * @author Hauke Mehrtens
 */
public class EIDInfoResultPlaceStructured implements EIDInfoResult, Serializable
{

  private static final long serialVersionUID = 2L;


  private final String street;

  private final String city;

  private final String state;

  private final String country;

  private final String zipCode;


  EIDInfoResultPlaceStructured(String street, String city, String state, String country, String zipCode)
  {
    this.street = street;
    this.city = city;
    this.state = state;
    this.country = country;
    this.zipCode = zipCode;
  }

  public String getStreet()
  {
    return street;
  }

  public String getCity()
  {
    return city;
  }

  public String getState()
  {
    return state;
  }

  public String getCountry()
  {
    return country;
  }

  public String getZipCode()
  {
    return zipCode;
  }

  @Override
  public String toString()
  {
    return country + ";" + state + ";" + zipCode + ";" + city + ";" + street;
  }

  @Override
  public int hashCode()
  {
    final int prime = 31;
    int result = prime + ((city == null) ? 0 : city.hashCode());
    result = prime * result + ((country == null) ? 0 : country.hashCode());
    result = prime * result + ((state == null) ? 0 : state.hashCode());
    result = prime * result + ((street == null) ? 0 : street.hashCode());
    result = prime * result + ((zipCode == null) ? 0 : zipCode.hashCode());
    return result;
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
    EIDInfoResultPlaceStructured other = (EIDInfoResultPlaceStructured)obj;
    if (city == null)
    {
      if (other.city != null)
      {
        return false;
      }
    }
    else if (!city.equals(other.city))
    {
      return false;
    }
    if (country == null)
    {
      if (other.country != null)
      {
        return false;
      }
    }
    else if (!country.equals(other.country))
    {
      return false;
    }
    if (state == null)
    {
      if (other.state != null)
      {
        return false;
      }
    }
    else if (!state.equals(other.state))
    {
      return false;
    }
    if (street == null)
    {
      if (other.street != null)
      {
        return false;
      }
    }
    else if (!street.equals(other.street))
    {
      return false;
    }
    if (zipCode == null)
    {
      if (other.zipCode != null)
      {
        return false;
      }
    }
    else if (!zipCode.equals(other.zipCode))
    {
      return false;
    }
    return true;
  }

}
