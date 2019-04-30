/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.BirthNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GenderAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PlaceOfBirthAttribute;


public enum EidasNaturalPersonAttributes implements EidasPersonAttributes
{
  FIRST_NAME("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
            "FirstName",
            GivenNameAttribute.class),
  BIRTH_NAME("http://eidas.europa.eu/attributes/naturalperson/BirthName",
            "BirthName",
            BirthNameAttribute.class),
  FAMILY_NAME("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
             "FamilyName",
             FamilyNameAttribute.class),
  DATE_OF_BIRTH("http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
              "DateOfBirth",
              DateOfBirthAttribute.class),
  PLACE_OF_BIRTH("http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth",
               "PlaceOfBirth",
               PlaceOfBirthAttribute.class),
  GENDER("http://eidas.europa.eu/attributes/naturalperson/Gender", "Gender", GenderAttribute.class),
  CURRENT_ADDRESS("http://eidas.europa.eu/attributes/naturalperson/CurrentAddress",
                 "CurrentAddress",
                 CurrentAddressAttribute.class),
  PERSON_IDENTIFIER("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                   "PersonIdentifier",
                   PersonIdentifierAttribute.class);

  public final String value;

  public final String friendlyName;

  public final Class<? extends EidasAttribute> attributeClass;

  EidasNaturalPersonAttributes(String value, String friendlyName, Class<? extends EidasAttribute> attrClass)
  {
    this.value = value;
    this.friendlyName = friendlyName;
    this.attributeClass = attrClass;
  }

  public static EidasNaturalPersonAttributes getValueOf(String s) throws ErrorCodeException
  {
    for ( EidasNaturalPersonAttributes enpa : EidasNaturalPersonAttributes.values() )
    {
      if (enpa.value.equals(s))
      {
        return enpa;
      }
    }
    throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX,
                                 "Unsupported EidasNaturalPersonAttributes value:" + s);
  }

  /**
   * Create an instance of the EidasAttribute corresponding to the NaturalPersonAttribute type
   *
   * @return instance of EidasAttribute corresponding to the NaturalPersonAttribute type
   */
  @Override
  public EidasAttribute getInstance()
  {
    try
    {
      return attributeClass.newInstance();
    }
    catch (InstantiationException | IllegalAccessException e)
    {
      throw new IllegalStateException("Unable to instantiate attribute type.", e);
    }
  }

  @Override
  public String getValue()
  {
    return value;
  }

  @Override
  public String getFriendlyName()
  {
    return friendlyName;
  }
}
