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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;

import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.AbstractEidasAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.NoArgsConstructor;


@NoArgsConstructor
public class DateOfBirthAttribute extends AbstractEidasAttribute
{

  public DateOfBirthAttribute(String date)
  {
    super(date);
  }

  public DateOfBirthAttribute(Date date)
  {
    super(new SimpleDateFormat("yyyy-MM-dd", Locale.GERMANY).format(date));
  }

  @Override
  public EidasPersonAttributes type()
  {
    return EidasNaturalPersonAttributes.DATE_OF_BIRTH;
  }

  @Override
  public Attribute generate()
  {
    Attribute attr = super.generate();
    XSAny dobt = new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, type().getQName());
    dobt.setTextContent(getValue());
    attr.getAttributeValues().add(dobt);
    return attr;
  }
}
