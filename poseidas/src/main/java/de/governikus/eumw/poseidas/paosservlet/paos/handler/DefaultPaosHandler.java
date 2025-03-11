/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.paosservlet.paos.handler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.xml.namespace.QName;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPEnvelope;
import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPHeader;
import jakarta.xml.soap.SOAPMessage;

import de.governikus.eumw.poseidas.paosservlet.authentication.paos.Util;

import iso.std.iso_iec._24727.tech.schema.StartPAOS;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class DefaultPaosHandler extends AbstractPaosHandler
{

  private static final String HTTP_WWW_W3_ORG_2005_03_ADDRESSING = "http://www.w3.org/2005/03/addressing";

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

  private final String relatesTo;

  private final String messageId;


  DefaultPaosHandler(HttpServletRequest request, byte[] requestBody) throws PaosHandlerException, IOException
  {
    super(request, requestBody);

    // conversationObject == null --> parsing failed, will result in StartPAOSResponse
    if (conversationObject != null && !getSessionManager().sessionIdExistsOrCanBeCreated(sessionId))
    {
      throw new PaosHandlerException("Cannot find session for ID : " + sessionId, 403);
    }

    relatesTo = Util.getHeaderValue(soapMessage, HTTP_WWW_W3_ORG_2005_03_ADDRESSING, "MessageID");
    messageId = Util.generateUUID();

  }

  /**
   * Must be called <b>after</b> the session lock was obtained.
   */
  void updateMessageID()
  {
    String oldMessageID = Util.getHeaderValue(soapMessage, HTTP_WWW_W3_ORG_2005_03_ADDRESSING, "RelatesTo");

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
  public String getSessionId()
  {
    if (conversationObject instanceof StartPAOS startPAOS)
    {
      return startPAOS.getSessionIdentifier();
    }

    String oldMessageID = Util.getHeaderValue(soapMessage, HTTP_WWW_W3_ORG_2005_03_ADDRESSING, "RelatesTo");
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

  /**
   * Overwritten to update the message id after the session lock was obtained.
   *
   * @param servletResponse the HTTP servlet response to write the PAOS message.
   * @throws IOException
   */
  @Override
  public void writeResponse(HttpServletResponse servletResponse) throws IOException, PaosHandlerException
  {
    updateMessageID();
    super.writeResponse(servletResponse);
  }

  @Override
  protected String createPAOSMessage(Object object)
    throws IOException, SOAPException
  {

    MessageFactory messageFactory = MessageFactory.newInstance();
    SOAPMessage soapResponse = messageFactory.createMessage();
    SOAPEnvelope soapEnvelope = soapResponse.getSOAPPart().getEnvelope();
    SOAPHeader soapHeader = soapEnvelope.getHeader();

    if (relatesTo != null)
    {
      soapHeader.addHeaderElement(new QName(HTTP_WWW_W3_ORG_2005_03_ADDRESSING, "RelatesTo")).setTextContent(relatesTo);
    }
    soapHeader.addHeaderElement(new QName(HTTP_WWW_W3_ORG_2005_03_ADDRESSING, "MessageID")).setTextContent(messageId);

    try
    {
      Marshaller m = JAXB_CONTEXT.createMarshaller();
      m.marshal(object, soapEnvelope.getBody());
    }
    catch (JAXBException e)
    {
      log.warn("Could not marshal object into SOAP message. Error Message: {}", e.getMessage());
      log.debug("Stack trace:", e);
    }

    try (ByteArrayOutputStream baos = new ByteArrayOutputStream())
    {
      soapResponse.writeTo(baos);
      return baos.toString();
    }
  }
}
