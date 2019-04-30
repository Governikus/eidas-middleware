/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;



public enum GenderType
{

  MALE("Male"), FEMALE("Female"), UNSPECIFIED("Unspecified");

  public final String value;

  private GenderType(String value)
  {
    this.value = value;
  }

  public static GenderType getValueOf(String s)
  {
    if (MALE.value.equalsIgnoreCase(s.trim()))
    {
      return MALE;
    }

    if (FEMALE.value.equalsIgnoreCase(s.trim()))
    {
      return FEMALE;
    }

    if (UNSPECIFIED.value.equalsIgnoreCase(s.trim()))
    {
      return UNSPECIFIED;
    }

    return null;
  }

}
