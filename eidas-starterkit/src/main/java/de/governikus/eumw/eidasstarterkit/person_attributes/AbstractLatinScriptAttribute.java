/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes;

import de.governikus.eumw.eidasstarterkit.EidasAttribute;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


public abstract class AbstractLatinScriptAttribute implements EidasAttribute
{

  public AbstractLatinScriptAttribute()
  {

  }

  private String latinScript;

  public AbstractLatinScriptAttribute(String latinScript)
  {
    this.latinScript = latinScript;
  }

  @Override
  public String getLatinScript()
  {
    return this.latinScript;
  }

  @Override
  public void setLatinScript(String latinScript)
  {
    this.latinScript = latinScript;
  }

  /**
   * Return the template used for the generation of XML
   *
   * @return The template of the NameAttribute, which will be used to create the XML representation of the
   *         attribute.
   */
  public abstract String getTemplateName();

  @Override
  public String generate()
  {
    String template = TemplateLoader.getTemplateByName(getTemplateName());
    return template.replace("$latinScript", this.latinScript);
  }

}
