/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.legal_persons_attributes;

import de.governikus.eumw.eidasstarterkit.EidasLegalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.AbstractLatinScriptAttribute;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;


/**
 * Created by yuri on 2/12/2016.
 */
public class EUIdentifierAttribute extends AbstractLatinScriptAttribute
{

  public EUIdentifierAttribute()
  {}

  public EUIdentifierAttribute(String value)
  {
    super(value);
  }

  @Override
  public String getTemplateName()
  {
    return "d201217euidentifier";
  }

  @Override
  public EidasAttributeType type()
  {
    return EidasAttributeType.D_2012_17_EU_IDENTIFIER;
  }

  @Override
  public EidasPersonAttributes getPersonAttributeType()
  {
    return EidasLegalPersonAttributes.D2012_17_EU_IDENTIFIER;
  }
}
