/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config.schema.xml;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.apache.commons.lang3.StringUtils;
import org.xml.sax.SAXException;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;


/**
 * project: eumw <br>
 * author: Pascal Knueppel <br>
 * created at: 18.09.2017 - 12:33 <br>
 * <br>
 * this class should provide utility helper methods for XML
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class XmlHelper
{

  /**
   * this method will marshal any element that is annotated with
   * {@link javax.xml.bind.annotation.XmlRootElement}
   *
   * @param object the annotated xml-object
   * @return the string representation of the xml-object
   */
  public static String marshalObject(Object object)
  {
    try
    {
      JAXBContext jc = JAXBContext.newInstance(object.getClass());
      Marshaller marshaller = jc.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
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
   * this method will be used to unmarshal a XML string into a POJO
   * 
   * @param xml the xml string that should be unmarshalled
   * @param clazz the destination class that will be able to hold the data of the XML structure
   * @return the unmarshalled POJO
   */
  public static <T> T unmarshal(String xml, Class<T> clazz)
  {
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
      return false;
    }
    else if (StringUtils.isBlank(schemaLocation.getFile()))
    {
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
      return false;
    }
    catch (IOException e)
    {
      return false;
    }
  }

}
