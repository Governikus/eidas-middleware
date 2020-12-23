package de.governikus.eumw.eidasstarterkit.person_attributes.natural_persons_attribute;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Attribute;
import org.w3c.dom.Element;

import de.governikus.eumw.eidascommon.Utils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;


@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TestUtils
{

  static final String NAME = "name";

  static final String LATIN_SCRIPT_FALSE = "LatinScript=\"false\"";

  static final String ONASIS = "\u03A9\u03BD\u03AC\u03C3\u03B7\u03C2";

  public static String attributeToString(Attribute attribute)
    throws MarshallingException, TransformerException, IOException
  {
    Marshaller rm = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                                                    .getMarshaller(attribute.getElementQName());
    Element all = rm.marshall(attribute);
    byte[] returnValue;
    Transformer trans = Utils.getTransformer();
    trans.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
    {
      trans.transform(new DOMSource(all), new StreamResult(bout));
      returnValue = bout.toByteArray();
    }
    return new String(returnValue, StandardCharsets.UTF_8);
  }
}
