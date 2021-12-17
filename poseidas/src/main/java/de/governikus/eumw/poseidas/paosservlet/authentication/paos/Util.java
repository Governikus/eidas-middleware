/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.authentication.paos;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.UUID;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.validation.SchemaFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.sun.org.apache.xerces.internal.util.XMLCatalogResolver;

import de.governikus.eumw.eidascommon.Utils;


public final class Util
{

  private static final ThreadLocal<DocumentBuilder> docBuilder = new ThreadLocal<>();


  public static Document xml2document(InputStream documentStream)
    throws SAXException, IOException, ParserConfigurationException
  {
    // synchronized is not needed, no problem when this happens two times
    if (docBuilder.get() == null)
    {
      docBuilder.set(Utils.getDocumentBuilder());
    }
    Document result = docBuilder.get().parse(documentStream);
    // Remove the ThreadLocal variable to prevent memory leaks
    docBuilder.remove();
    return result;
  }

  public static Object unmarshalFirstSoapBodyElement(InputStream inputStream)
    throws SAXException, JAXBException, IOException, ParserConfigurationException
  {
    Document soapRequest = Util.xml2document(inputStream);

    // 1) Search for SOAP-Body
    Node soapBody = soapRequest.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Body")
                               .item(0);
    if (soapBody != null)
    {
      // 2) First element of body
      Node child = soapBody.getFirstChild();
      while (child != null && child.getNodeType() != Node.ELEMENT_NODE)
      {
        child = child.getNextSibling();
      }
      if (child != null)
      {
        JAXBContext context = JAXBContext.newInstance("iso.std.iso_iec._24727.tech.schema");
        Unmarshaller um = context.createUnmarshaller();
        SchemaFactory sf = Utils.getSchemaFactory();
        // we must permit file access for there are some schema files referenced in the catalog
        sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "file");
        String catalogUrlString = Util.class.getResource("/ecard115/ecard115catalog.xml").toString();

        URL schemaUrl = Util.class.getResource("/ecard115/ISO24727-Protocols.xsd");
        sf.setResourceResolver(new XMLCatalogResolver(new String[]{catalogUrlString}));
        try
        {
          um.setSchema(sf.newSchema(schemaUrl));
          return um.unmarshal(child);
        }
        catch (SAXException e)
        {
          // the catalog might be outdated, force regeneration
        }
      }
    }
    return null;
  }

  public static String generateUUID()
  {
    String uuid = UUID.randomUUID().toString();
    return "urn:uuid:" + uuid;
  }

  public static SOAPMessage unmarshalSOAPMessage(InputStream in) throws IOException, SOAPException
  {
    MessageFactory factory = MessageFactory.newInstance();
    return factory.createMessage(null, in);
  }

  public static String getHeaderValue(SOAPMessage msg, String nmsp, String name)
  {
    try
    {
      SOAPHeader header = msg.getSOAPHeader();
      NodeList nodes = header.getElementsByTagNameNS(nmsp, name);
      if (nodes.getLength() == 1)
      {
        return nodes.item(0).getTextContent();
      }
    }
    catch (Exception e)
    {}
    return null;
  }

  private Util()
  {}
}
