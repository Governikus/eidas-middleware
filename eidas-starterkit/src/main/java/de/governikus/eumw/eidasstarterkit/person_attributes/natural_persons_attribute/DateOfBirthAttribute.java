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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


public class DateOfBirthAttribute implements EidasAttribute
{

  private String dateOfBirth;

  public DateOfBirthAttribute()
  {}

  public DateOfBirthAttribute(String date)
  {
    super();
    this.dateOfBirth = date;
  }

  public DateOfBirthAttribute(Date date)
  {
    super();
    this.dateOfBirth = new SimpleDateFormat("yyyy-MM-dd", Locale.GERMANY).format(date);
  }

  public String getDate()
  {
    return dateOfBirth;
  }

  @Override
  public String generate()
  {
    return TemplateLoader.getTemplateByName("dateOfBirth").replace("$value", this.dateOfBirth);
  }

  @Override
  public EidasAttributeType type()
  {
    return EidasAttributeType.DATE_OF_BIRTH;
  }

  @Override
  public String toString()
  {
    return type() + " " + getDate();
  }

  @Override
  public EidasPersonAttributes getPersonAttributeType()
  {
    return EidasNaturalPersonAttributes.DATE_OF_BIRTH;
  }

  @Override
  public void setLatinScript(String value)
  {
    this.dateOfBirth = value;
  }

  @Override
  public String getLatinScript()
  {
    return getDate();
  }

}
