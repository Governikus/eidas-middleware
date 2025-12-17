/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;

import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public abstract class AbstractEidasAttribute implements EidasAttribute
{

  private String value;

  @Override
  public Attribute generate()
  {
    Attribute attribute = new AttributeBuilder().buildObject();
    attribute.setFriendlyName(type().getFriendlyName());
    attribute.setName(type().getName());
    attribute.setNameFormat(Attribute.URI_REFERENCE);
    return attribute;
  }

  @Override
  public String toString()
  {
    return type().getFriendlyName() + " " + getValue();
  }
}
