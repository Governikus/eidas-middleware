/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

import de.governikus.eumw.eidasstarterkit.template.TemplateLoader;


public class BirthNameAttributeTest
{

  @Test
  public void testGenerateBirthNameAttributeWithNonLatinScript() throws IOException
  {
    TemplateLoader.init();
    BirthNameAttribute attribute = new BirthNameAttribute("name", "\u03A9\u03BD\u03AC\u03C3\u03B7\u03C2");
    String xml = attribute.generate();
    System.out.println(xml);
    Assert.assertTrue(xml.contains("LatinScript=\"false\">"));
    Assert.assertTrue(xml.contains("\u03A9\u03BD\u03AC\u03C3\u03B7\u03C2"));
  }

  @Test
  public void testGenerateBirthNameAttributeEmptyNonLatin() throws IOException
  {
    TemplateLoader.init();
    BirthNameAttribute attribute = new BirthNameAttribute("name", "");
    String xml = attribute.generate();
    System.out.println(xml);
    Assert.assertTrue(xml.contains("name"));
    Assert.assertFalse(xml.contains("LatinScript=\"false\">"));
  }

  @Test
  public void testGenerateBirthNameAttributeNullNonLatin() throws IOException
  {
    TemplateLoader.init();
    BirthNameAttribute attribute = new BirthNameAttribute("name", null);
    String xml = attribute.generate();
    System.out.println(xml);
    Assert.assertTrue(xml.contains("name"));
    Assert.assertFalse(xml.contains("LatinScript=\"false\">"));
  }

  @Test
  public void testGenerateBirthNameAttribute() throws IOException
  {
    TemplateLoader.init();
    BirthNameAttribute attribute = new BirthNameAttribute("name");
    String xml = attribute.generate();
    System.out.println(xml);
    Assert.assertTrue(xml.contains("name"));
    Assert.assertFalse(xml.contains("LatinScript=\"false\">"));
  }

}
