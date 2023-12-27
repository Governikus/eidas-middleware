/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;

import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.AbstractEidasAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.NoArgsConstructor;
import se.swedenconnect.opensaml.eidas.ext.attributes.PlaceOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.impl.PlaceOfBirthTypeBuilder;


@NoArgsConstructor
public class PlaceOfBirthAttribute extends AbstractEidasAttribute
{

  public PlaceOfBirthAttribute(String value)
  {
    super(value);
  }

  @Override
  public EidasPersonAttributes type()
  {
    return EidasNaturalPersonAttributes.PLACE_OF_BIRTH;
  }

  @Override
  public Attribute generate()
  {
    Attribute attr = super.generate();
    PlaceOfBirthType pobt = new PlaceOfBirthTypeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                                                      type().getQName());
    pobt.setValue(getValue());
    attr.getAttributeValues().add(pobt);
    return attr;
  }
}
