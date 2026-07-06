package de.governikus.eumw.eidascommon;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;


class UtilsTest
{

  @Test
  void testGetDocumentBuilder() throws ParserConfigurationException
  {
    DocumentBuilder documentBuilder = Utils.getDocumentBuilder();
    Assertions.assertNotNull(documentBuilder);
  }

  @Test
  void testGetDocumentBuilderRejectsDoctype() throws Exception
  {
    DocumentBuilder documentBuilder = Utils.getDocumentBuilder();

    String xml = """
      <!DOCTYPE foo [
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <foo>&xxe;</foo>
      """;

    try (InputStream is = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
    {
      Assertions.assertThrows(SAXException.class, () -> documentBuilder.parse(is));
    }
  }

  @Test
  void testGetSaxParserFactory() throws Exception
  {
    SAXParserFactory factory = Utils.getSAXParserFactory();
    Assertions.assertNotNull(factory);
  }



}
