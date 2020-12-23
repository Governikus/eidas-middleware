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

import java.io.IOException;

import javax.xml.transform.TransformerException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Attribute;

import de.governikus.eumw.eidasstarterkit.EidasSaml;
import lombok.extern.slf4j.Slf4j;


@Slf4j
class FamilyNameAttributeTest
{

  @BeforeAll
  static void init() throws InitializationException
  {
    EidasSaml.init();
  }

  @Test
  void testGenerateFamilyNameAttributeWithNonLatinScript()
    throws IOException, TransformerException, MarshallingException
  {
    FamilyNameAttribute attribute = new FamilyNameAttribute(TestUtils.NAME, TestUtils.ONASIS);
    Attribute xml = attribute.generate();
    String attributeAsString = TestUtils.attributeToString(xml);
    log.debug(attributeAsString);
    Assertions.assertTrue(attributeAsString.contains(TestUtils.LATIN_SCRIPT_FALSE));
    Assertions.assertTrue(attributeAsString.contains(TestUtils.ONASIS));
  }

  @Test
  void testGenerateFamilyNameAttributeEmptyNonLatin()
    throws IOException, TransformerException, MarshallingException
  {
    FamilyNameAttribute attribute = new FamilyNameAttribute(TestUtils.NAME, "");
    Attribute xml = attribute.generate();
    String attributeAsString = TestUtils.attributeToString(xml);
    log.debug(attributeAsString);
    Assertions.assertTrue(attributeAsString.contains(TestUtils.NAME));
    Assertions.assertFalse(attributeAsString.contains(TestUtils.LATIN_SCRIPT_FALSE));
  }

  @Test
  void testGenerateFamilyNameAttributeNullNonLatin()
    throws IOException, TransformerException, MarshallingException
  {
    FamilyNameAttribute attribute = new FamilyNameAttribute(TestUtils.NAME, null);
    Attribute xml = attribute.generate();
    String attributeAsString = TestUtils.attributeToString(xml);
    log.debug(attributeAsString);
    Assertions.assertTrue(attributeAsString.contains(TestUtils.NAME));
    Assertions.assertFalse(attributeAsString.contains(TestUtils.LATIN_SCRIPT_FALSE));
  }

  @Test
  void testGenerateFamilyNameAttribute() throws IOException, TransformerException, MarshallingException
  {
    FamilyNameAttribute attribute = new FamilyNameAttribute(TestUtils.NAME);
    Attribute xml = attribute.generate();
    String attributeAsString = TestUtils.attributeToString(xml);
    log.debug(attributeAsString);
    Assertions.assertTrue(attributeAsString.contains(TestUtils.NAME));
    Assertions.assertFalse(attributeAsString.contains(TestUtils.LATIN_SCRIPT_FALSE));
  }
}
