package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.impl.AttributeMarshaller;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;


class DateOfBirthAttributeTest
{

  @BeforeAll
  static void init() throws Exception
  {
    OpenSAMLInitializer.getInstance().initialize(new OpenSAMLSecurityExtensionConfig());
    XMLObjectProviderRegistrySupport.deregisterObjectProvider(EidasNaturalPersonAttributes.DATE_OF_BIRTH.getQName());
  }

  @ParameterizedTest
  @ValueSource(strings = {"2063-04-05", "1920-00-01", "1920-01-00"})
  void testDateOfBirthAttributeString(String testDate) throws Exception
  {
    DateOfBirthAttribute dob = new DateOfBirthAttribute(testDate);
    Attribute attr = dob.generate();
    assertEquals(1, attr.getAttributeValues().size());
    assertEquals(EidasNaturalPersonAttributes.DATE_OF_BIRTH.getQName(),
                 attr.getAttributeValues().get(0).getSchemaType());
    assertFalse(attr.getAttributeValues().get(0).hasChildren());

    AttributeMarshaller marshaller = new AttributeMarshaller();
    Element all = marshaller.marshall(attr);

    Transformer trans = Utils.getTransformer();
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    trans.transform(new DOMSource(all), new StreamResult(bout));

    String attrString = bout.toString(StandardCharsets.UTF_8);
    assertTrue(attrString.contains(testDate));
  }
}
