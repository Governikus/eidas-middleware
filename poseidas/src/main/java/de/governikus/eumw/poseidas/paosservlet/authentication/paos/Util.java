/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.authentication.paos;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.UUID;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPBody;
import jakarta.xml.soap.SOAPElement;
import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPHeader;
import jakarta.xml.soap.SOAPMessage;

import org.w3c.dom.Node;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public final class Util
{

  private static final JAXBContext JAXB_CONTEXT;

  static
  {
    try
    {
      JAXB_CONTEXT = JAXBContext.newInstance("iso.std.iso_iec._24727.tech.schema");
    }
    catch (JAXBException e)
    {
      throw new RuntimeException("Cannot create JAXBContext for PAOS messages", e);
    }
  }

  public static Object unmarshalFirstSoapBodyElement(SOAPBody soapBody) throws JAXBException
  {
    if (soapBody != null)
    {
      Node child = soapBody.getFirstChild();
      while (child != null && child.getNodeType() != Node.ELEMENT_NODE)
      {
        child = child.getNextSibling();
      }
      if (child != null)
      {
        return JAXB_CONTEXT.createUnmarshaller().unmarshal(child);
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
      Iterator<jakarta.xml.soap.Node> childElements = header.getChildElements();
      while (childElements.hasNext())
      {
        jakarta.xml.soap.Node child = childElements.next();
        if (child instanceof SOAPElement soapElement)
        {
          if (name.equals(soapElement.getLocalName()) && nmsp.equals(soapElement.getNamespaceURI()))
          {
            return soapElement.getTextContent();
          }
        }
      }
    }
    catch (Exception e)
    {
      // We don't need to throw an exception here, because all callers checking for null.
      log.warn("Failed to parse SOAP header", e);
    }
    return null;
  }

  private Util()
  {}
}
