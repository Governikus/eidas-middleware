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

import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


public class GenderAttribute implements EidasAttribute
{

  private GenderType value;

  public GenderAttribute(GenderType value)
  {
    super();
    this.value = value;
  }

  public GenderAttribute()
  {}

  public String getNonLatinScript()
  {
    return value.value;
  }

  public void setValue(GenderType value)
  {
    this.value = value;
  }

  @Override
  public String generate()
  {
    return TemplateLoader.getTemplateByName("gender").replace("$value", value.value);
  }

  @Override
  public EidasAttributeType type()
  {
    return EidasAttributeType.GENDER;
  }

  @Override
  public EidasPersonAttributes getPersonAttributeType()
  {
    return EidasNaturalPersonAttributes.GENDER;
  }

  @Override
  public void setLatinScript(String value)
  {
    this.value = GenderType.getValueOf(value);
  }

  @Override
  public String getLatinScript()
  {
    return this.value.name();
  }


}
