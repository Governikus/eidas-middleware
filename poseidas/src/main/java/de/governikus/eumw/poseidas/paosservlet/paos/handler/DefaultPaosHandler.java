/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.paos.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import de.governikus.eumw.poseidas.ecardcore.utilities.XMLTransformer;
import de.governikus.eumw.poseidas.eidserver.convenience.session.Session;
import de.governikus.eumw.poseidas.paosservlet.authentication.paos.Util;
import iso.std.iso_iec._24727.tech.schema.StartPAOS;


public class DefaultPaosHandler extends AbstractPaosHandler
{

  private final String relatesTo, messageId;


  DefaultPaosHandler(HttpServletRequest request, byte[] requestBody)
    throws PaosHandlerException, IOException
  {
    super(request, requestBody);

    // conversationObject == null --> parsing failed, will result in StartPAOSResponse
    if (conversationObject != null)
    {
      Session session = getSessionManager().getSession(sessionId);
      if (session == null)
      {
        throw new PaosHandlerException("Cannot find session for ID : " + sessionId, 403);
      }
    }
    relatesTo = Util.getHeaderValue(soapMessage, "http://www.w3.org/2005/03/addressing", "MessageID");
    String oldMessageID = Util.getHeaderValue(soapMessage,
                                              "http://www.w3.org/2005/03/addressing",
                                              "RelatesTo");
    messageId = Util.generateUUID();

    if (oldMessageID == null)
    {
      MessageSessionMapper.getInstance().add(messageId, sessionId);
    }
    else
    {
      MessageSessionMapper.getInstance().overwriteMessageId(oldMessageID, messageId);
    }
  }

  @Override
  protected String getSessionId()
  {
    if (conversationObject instanceof StartPAOS)
    {
      return ((StartPAOS)conversationObject).getSessionIdentifier();
    }

    String oldMessageID = Util.getHeaderValue(soapMessage,
                                              "http://www.w3.org/2005/03/addressing",
                                              "RelatesTo");
    if (oldMessageID == null)
    {
      return null;
    }

    return MessageSessionMapper.getInstance().getSessionId(oldMessageID);
  }

  @Override
  protected void removeSession()
  {
    super.removeSession();
    MessageSessionMapper.getInstance().remove(messageId);
  }

  @Override
  protected String createPAOSMessage(Object object) throws SAXException, IOException, TransformerException,
    ParserConfigurationException
  {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (PrintWriter writer = new PrintWriter(out))
    {
      writer.println("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">");
      writer.println("   <soap:Header>");
      writer.println("      <sb:Correlation xmlns:sb=\"http://urn:liberty:sb:2003-08\"");
      writer.println("         messageID=\"" + generateUniqueID() + "\"");
      writer.println("         refToMessageID=\"" + sessionId + "\"/>");

      if (relatesTo != null)
      {
        writer.print("      <RelatesTo xmlns=\"http://www.w3.org/2005/03/addressing\""
                     + " mustUnderstand=\"1\" " + "actor=\"http://schemas.xmlsoap.org/soap/actor/next\""
                     + ">");
        writer.println(relatesTo + "</RelatesTo>");
      }
      writer.print("      <MessageID xmlns=\"http://www.w3.org/2005/03/addressing\">");
      writer.println(messageId + "</MessageID>");

      writer.println("   </soap:Header>");
      writer.println("   <soap:Body>");
      writer.println("   </soap:Body>");
      writer.println("</soap:Envelope>");
    }

    Document paosEnvelope = Util.xml2document(new ByteArrayInputStream(out.toByteArray()));
    Node soapBody = paosEnvelope.getElementsByTagName("soap:Body").item(0);

    try
    {
      JAXBContext context = JAXBContext.newInstance("iso.std.iso_iec._24727.tech.schema");
      Marshaller m = context.createMarshaller();
      m.marshal(object, soapBody);
    }
    catch (JAXBException e)
    {
      e.getCause();
    }

    return XMLTransformer.xmlToString(paosEnvelope);
  }
}
