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
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderTypeEnumeration;
import se.swedenconnect.opensaml.eidas.ext.attributes.impl.GenderTypeBuilder;


@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class GenderAttribute extends AbstractEidasAttribute
{

  private GenderType value;

  @Override
  public EidasPersonAttributes type()
  {
    return EidasNaturalPersonAttributes.GENDER;
  }

  @Override
  public void setValue(String value)
  {
    this.value = GenderType.getValueOf(value);
  }

  @Override
  public String getValue()
  {
    return this.value.getValue();
  }

  @Override
  public Attribute generate()
  {
    Attribute attr = super.generate();
    se.swedenconnect.opensaml.eidas.ext.attributes.GenderType gt = new GenderTypeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                                                                                type().getQName());
    gt.setGender(GenderTypeEnumeration.fromValue(getValue()));
    attr.getAttributeValues().add(gt);
    return attr;
  }
}
