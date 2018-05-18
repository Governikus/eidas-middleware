/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.utils.xml;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import lombok.extern.slf4j.Slf4j;


/**
 * this class should provide utility helper methods for XML
 */
@Slf4j
public final class XmlHelper
{

  /**
   * utility class constructor
   */
  private XmlHelper()
  {
    super();
  }
  
  /**
   * this method will marshal any element that is annotated with
   * {@link javax.xml.bind.annotation.XmlRootElement}
   *
   * @param object the annotated xml-object
   * @return the string representation of the xml-object
   */
  public static String marshalObject(Object object)
  {
    if (log.isTraceEnabled())
    {
      log.trace("translating java instance of type '{}' to a xml-string.", object.getClass());
    }
    try
    {
      JAXBContext jc = JAXBContext.newInstance(object.getClass());
      Marshaller marshaller = jc.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      marshaller.setProperty(Marshaller.JAXB_ENCODING, StandardCharsets.UTF_8.name());
      final StringWriter w = new StringWriter();
      marshaller.marshal(object, w);
      return w.toString();
    }
    catch (JAXBException e)
    {
      throw new XmlException("error while marshalling class " + object.getClass().getName(), e);
    }
  }

  /**
   * this method will marshal any element that is annotated with
   * {@link javax.xml.bind.annotation.XmlRootElement} into a file
   *
   * @param object the annotated xml-object
   * @param pathname the file path to the created xml file
   */
  public static void marshalObjectToFile(Object object, String pathname)
  {
    if (log.isTraceEnabled())
    {
      log.trace("translating java instance of type '{}' to a xml-string.", object.getClass());
    }
    try
    {
      JAXBContext jc = JAXBContext.newInstance(object.getClass());
      Marshaller marshaller = jc.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      marshaller.setProperty(Marshaller.JAXB_ENCODING, StandardCharsets.UTF_8.name());
      marshaller.marshal(object, new File(pathname));
    }
    catch (JAXBException e)
    {
      throw new XmlException("error while marshalling class " + object.getClass().getName(), e);
    }
  }

  /**
   * this method will be used to unmarshal a XML string into a POJO
   * 
   * @param xml the xml string that should be unmarshalled
   * @param clazz the destination class that will be able to hold the data of the XML structure
   * @return the unmarshalled POJO
   */
  public static <T> T unmarshal(String xml, Class<T> clazz)
  {
    if (log.isTraceEnabled())
    {
      log.trace("unmarshalling xml '{}' to object of type '{}'.", xml, clazz);
    }
    try
    {
      JAXBContext jaxbContext = JAXBContext.newInstance(clazz);
      Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
      return (T)jaxbUnmarshaller.unmarshal(new StringReader(xml));
    }
    catch (Exception ex)
    {
      throw new XmlException("could not parse given XML \n'" + xml + "'\n", ex);
    }
  }

  /**
   * this method will be used to unmarshal a XML file into a POJO
   *
   * @param xmlFile the xml file that should be unmarshalled
   * @param clazz the destination class that will be able to hold the data of the XML structure
   * @return the unmarshalled POJO
   */
  public static <T> T unmarshal(File xmlFile, Class<T> clazz)
  {
    if (log.isTraceEnabled())
    {
      log.trace("unmarshalling xml file '{}' to object of type '{}'.", xmlFile, clazz);
    }
    try
    {
      JAXBContext jaxbContext = JAXBContext.newInstance(clazz);
      Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
      return (T)jaxbUnmarshaller.unmarshal(xmlFile);
    }
    catch (Exception ex)
    {
      throw new XmlException("could not parse given XML \n'" + xmlFile + "'\n", ex);
    }
  }

  /**
   * will parse the given String into a w3c dom document
   * 
   * @param xml the XML string to be parsed
   * @return the dom document with the XML string representation
   */
  public static Document toDocument(String xml)
  {
    if (log.isTraceEnabled())
    {
      log.trace("translating xml '{}' to dom document.", xml);
    }
    try
    {
      DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
      InputSource is = new InputSource();
      is.setCharacterStream(new StringReader(xml));
      return db.parse(is);
    }
    catch (Exception ex)
    {
      throw new XmlException("could not parse given XML \n'" + xml + "'\n", ex);
    }
  }

  /**
   * will parse a given XML DOM document to a string representation
   * 
   * @param document the document to parse
   * @return the string representation of the DOM document
   */
  public static String documentToString(Document document)
  {
    try
    {
      StringWriter sw = new StringWriter();
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
      transformer.setOutputProperty(OutputKeys.METHOD, "xml");
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
      transformer.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());

      transformer.transform(new DOMSource(document), new StreamResult(sw));
      return sw.toString();
    }
    catch (Exception ex)
    {
      throw new XmlException("could not parse XML DOM document to string...", ex);
    }
  }

  /**
   * this method will take some input xml and will check it against its schema
   *
   * @param pojo the input object that will be converted into a XML string and checked against the schema
   * @param schemaLocation the schema that should be used to check the XML
   * @return true if the check succedded, false else
   */
  public static boolean checkXmlAgainstSchema(Object pojo, URL schemaLocation)
  {
    String xml = marshalObject(pojo);
    return checkXmlAgainstSchema(xml, schemaLocation);
  }

  /**
   * this method will take some input xml and will check it against its schema
   * 
   * @param inputXml the XML that should be checked against its schema
   * @param schemaLocation the schema that should be used to check the XML
   * @return true if the check succedded, false else
   */
  public static boolean checkXmlAgainstSchema(String inputXml, URL schemaLocation)
  {
    if (schemaLocation == null)
    {
      log.error("schema location is null...");
      return false;
    }
    else if (StringUtils.isBlank(schemaLocation.getFile()))
    {
      log.error("schema location '{}' does not exist...", schemaLocation);
      return false;
    }
    // build the schema
    SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
    Schema schema = null;
    try
    {
      schema = factory.newSchema(schemaLocation);
    }
    catch (SAXException e)
    {
      log.error(e.getMessage(), e);
      return false;
    }
    Validator validator = schema.newValidator();

    // create a source from a string
    Source source = new StreamSource(new StringReader(inputXml));

    try
    {
      validator.validate(source);
      return true;
    }
    catch (SAXException e)
    {
      if (log.isErrorEnabled())
      {
        log.error("schema validation for xml conent '" + inputXml + "' has failed", e);
      }
      return false;
    }
    catch (IOException e)
    {
      if (log.isErrorEnabled())
      {
        log.error("xml input could not be checked against schema.", e);
        log.error("invalid xml is: {}", inputXml);
      }
      return false;
    }
  }

  /**
   * Pretty Print XML String with indentsize of 2
   *
   * @param xml the not pretty printed xml representation
   * @return the pretty printed xml
   */
  public static String prettyPrintXml(String xml)
  {
    return prettyPrintXml(xml, 2);
  }

  /**
   * Tries to format the given xml with the given indent size
   * 
   * @param xml the not pretty printed xml representation
   * @param indentSize the indentsize of the xml
   * @return the pretty printed xml
   */
  public static String prettyPrintXml(String xml, int indentSize)
  {
    Transformer transformer = null;
    try
    {
      transformer = TransformerFactory.newInstance().newTransformer();
    }
    catch (TransformerConfigurationException e)
    {
      throw new IllegalStateException("cannot create transformer factory for XML", e);
    }
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", String.valueOf(indentSize));
    // initialize StreamResult with File object to save to file
    StreamResult result = new StreamResult(new StringWriter());
    StreamSource streamSource = new StreamSource(new ByteArrayInputStream(xml.getBytes()));
    try
    {
      transformer.transform(streamSource, result);
    }
    catch (TransformerException e)
    {
      if (log.isErrorEnabled())
      {
        log.error("could not pretty print xml: " + xml, e);
      }
      return null;
    }
    return result.getWriter().toString();
  }

  /**
   * Will check if the given xml string is a valid xml representation
   * 
   * @param xml string representation to check
   * @return true if the xml representation is not erroneous, false else
   */
  public static boolean isXmlWellFormed(String xml)
  {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setValidating(false);
    factory.setNamespaceAware(true);

    DocumentBuilder builder = null;
    try (ByteArrayInputStream inputStream = new ByteArrayInputStream(xml.getBytes()))
    {
      builder = factory.newDocumentBuilder();
      // the "parse" method also validates XML, will throw an exception if misformatted
      builder.parse(new InputSource(inputStream));
      return true;
    }
    catch (ParserConfigurationException | SAXException | IOException e)
    {
      return false;
    }
  }

}
