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

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;

import de.governikus.eumw.eidascommon.Utils;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import se.swedenconnect.opensaml.eidas.ext.attributes.TransliterationStringType;


@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public abstract class AbstractNonLatinScriptAttribute extends AbstractEidasAttribute
{

  private String nonLatinScript;

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

  @Override
  public Attribute generate()
  {
    Attribute attr = super.generate();
    TransliterationStringType tst = (TransliterationStringType)XMLObjectProviderRegistrySupport.getBuilderFactory()
                                                                                               .getBuilder(type().getQName())
                                                                                               .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                                                                                            type().getQName());
    tst.setLatinScript(true);
    tst.setValue(getValue());
    attr.getAttributeValues().add(tst);
    if (!Utils.isNullOrEmpty(this.nonLatinScript))
    {
      tst = (TransliterationStringType)XMLObjectProviderRegistrySupport.getBuilderFactory()
                                                                       .getBuilder(type().getQName())
                                                                       .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                                                                    type().getQName());
      tst.setLatinScript(false);
      tst.setValue(this.nonLatinScript);
      attr.getAttributeValues().add(tst);
    }
    return attr;
  }

  @Override
  public String toString()
  {
    return type().getFriendlyName() + " " + (nonLatinScript == null ? getValue() : nonLatinScript);
  }
}
