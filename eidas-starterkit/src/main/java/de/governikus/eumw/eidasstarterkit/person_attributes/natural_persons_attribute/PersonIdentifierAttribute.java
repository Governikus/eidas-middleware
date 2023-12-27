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
import se.swedenconnect.opensaml.eidas.ext.attributes.PersonIdentifierType;
import se.swedenconnect.opensaml.eidas.ext.attributes.impl.PersonIdentifierTypeBuilder;


@NoArgsConstructor
public class PersonIdentifierAttribute extends AbstractEidasAttribute
{

  public PersonIdentifierAttribute(String id)
  {
    super(id);
  }

  @Override
  public EidasPersonAttributes type()
  {
    return EidasNaturalPersonAttributes.PERSON_IDENTIFIER;
  }

  @Override
  public Attribute generate()
  {
    Attribute attr = super.generate();
    PersonIdentifierType pit = new PersonIdentifierTypeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                                                             type().getQName());
    pit.setValue(getValue());
    attr.getAttributeValues().add(pit);
    return attr;
  }
}
