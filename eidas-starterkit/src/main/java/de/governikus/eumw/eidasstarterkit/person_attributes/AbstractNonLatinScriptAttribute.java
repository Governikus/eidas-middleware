/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


public abstract class AbstractNonLatinScriptAttribute extends AbstractLatinScriptAttribute
{

  private String nonLatinScript;

  public AbstractNonLatinScriptAttribute()
  {

  }

  public AbstractNonLatinScriptAttribute(String latinScript)
  {
    super(latinScript);
    this.nonLatinScript = null;
  }

  public AbstractNonLatinScriptAttribute(String latinScript, String nonLatinScript)
  {
    super(latinScript);
    this.nonLatinScript = nonLatinScript;
  }

  public String getNonLatinScript()
  {
    return this.nonLatinScript;
  }

  public void setNonLatinScript(String nonLatinScript)
  {
    this.nonLatinScript = nonLatinScript;
  }

  /**
   * Return the template used for the generation of XML
   *
   * @return The template of the NameAttribute, which will be used to create the XML representation of the
   *         attribute.
   */
  @Override
  public abstract String getTemplateName();

  @Override
  public String generate()
  {
    String template = TemplateLoader.getTemplateByName(getTemplateName());
    if (Utils.isNullOrEmpty(this.nonLatinScript))
    {
      return template.replace("$latinScript", super.getLatinScript());
    }
    else
    {
      return template.replace("$latinScript", super.getLatinScript()).replace("$nonLatinScript",
                                                                              this.nonLatinScript);
    }
  }

  @Override
  public String toString()
  {
    return type() + " " + (getNonLatinScript() == null ? getLatinScript() : getNonLatinScript());
  }
}
