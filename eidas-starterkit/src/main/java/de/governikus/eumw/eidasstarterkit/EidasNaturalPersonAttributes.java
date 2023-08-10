/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit;

import javax.xml.namespace.QName;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidasstarterkit.additional.attributes.NationalityType;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.BirthNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.CurrentAddressAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.DateOfBirthAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.FamilyNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GenderAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.GivenNameAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.NationalityAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PersonIdentifierAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute.PlaceOfBirthAttribute;
import lombok.AllArgsConstructor;
import lombok.Getter;
import se.litsec.eidas.opensaml.ext.attributes.AttributeConstants;
import se.litsec.eidas.opensaml.ext.attributes.BirthNameType;
import se.litsec.eidas.opensaml.ext.attributes.CurrentAddressType;
import se.litsec.eidas.opensaml.ext.attributes.CurrentFamilyNameType;
import se.litsec.eidas.opensaml.ext.attributes.CurrentGivenNameType;
import se.litsec.eidas.opensaml.ext.attributes.DateOfBirthType;
import se.litsec.eidas.opensaml.ext.attributes.GenderType;
import se.litsec.eidas.opensaml.ext.attributes.PersonIdentifierType;
import se.litsec.eidas.opensaml.ext.attributes.PlaceOfBirthType;


@AllArgsConstructor
public enum EidasNaturalPersonAttributes implements EidasPersonAttributes
{
  FIRST_NAME(AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME,
             AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_FRIENDLY_NAME,
             CurrentGivenNameType.TYPE_NAME,
             GivenNameAttribute.class),
  BIRTH_NAME(AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_NAME,
             AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_FRIENDLY_NAME,
             BirthNameType.TYPE_NAME,
             BirthNameAttribute.class),
  FAMILY_NAME(AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME,
              AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_FRIENDLY_NAME,
              CurrentFamilyNameType.TYPE_NAME,
              FamilyNameAttribute.class),
  DATE_OF_BIRTH(AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_NAME,
                AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
                DateOfBirthType.TYPE_NAME,
                DateOfBirthAttribute.class),
  PLACE_OF_BIRTH(AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_NAME,
                 AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
                 PlaceOfBirthType.TYPE_NAME,
                 PlaceOfBirthAttribute.class),
  GENDER(AttributeConstants.EIDAS_GENDER_ATTRIBUTE_NAME,
         AttributeConstants.EIDAS_GENDER_ATTRIBUTE_FRIENDLY_NAME,
         GenderType.TYPE_NAME,
         GenderAttribute.class),
  CURRENT_ADDRESS(AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_NAME,
                  AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_FRIENDLY_NAME,
                  CurrentAddressType.TYPE_NAME,
                  CurrentAddressAttribute.class),
  PERSON_IDENTIFIER(AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_NAME,
                    AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_FRIENDLY_NAME,
                    PersonIdentifierType.TYPE_NAME,
                    PersonIdentifierAttribute.class),
  NATIONALITY(NationalityAttribute.NATIONALITY_ATTRIBUTE_NAME,
              NationalityAttribute.NATIONALITY_ATTRIBUTE_FRIENDLY_NAME,
              NationalityType.TYPE_NAME,
              NationalityAttribute.class);

  @Getter
  private final String name;

  @Getter
  private final String friendlyName;

  @Getter
  private final QName qName;

  private final Class<? extends EidasAttribute> attributeClass;

  public static EidasNaturalPersonAttributes getValueOf(String s) throws ErrorCodeException
  {
    for ( EidasNaturalPersonAttributes enpa : EidasNaturalPersonAttributes.values() )
    {
      if (enpa.name.equals(s))
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
}
