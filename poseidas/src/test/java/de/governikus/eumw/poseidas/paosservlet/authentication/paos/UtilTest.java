package de.governikus.eumw.poseidas.paosservlet.authentication.paos;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.MimeHeaders;
import jakarta.xml.soap.SOAPMessage;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


class UtilTest
{

  private static final String SOAP_MESSAGE_WITH_MESSAGE_ID = """
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:paos="urn:liberty:paos:2006-08" xmlns:wsa="http://www.w3.org/2005/03/addressing" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1" xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
        <soap:Header>
            <paos:PAOS soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next">
                <paos:Version>urn:liberty:paos:2006-08</paos:Version>
                <paos:EndpointReference>
                    <paos:Address>http://www.projectliberty.org/2006/01/role/paos</paos:Address>
                    <paos:MetaData>
                        <paos:ServiceType>http://www.bsi.bund.de/ecard/api/1.1/PAOS/GetNextCommand</paos:ServiceType>
                    </paos:MetaData>
                </paos:EndpointReference>
            </paos:PAOS>
            <wsa:ReplyTo>
                <wsa:Address>http://www.projectliberty.org/2006/02/role/paos</wsa:Address>
            </wsa:ReplyTo>
            <wsa:MessageID>urn:uuid:5f8dd8ff-83bd-efb1-d339-f86ca6303acf</wsa:MessageID>
        </soap:Header>
        <soap:Body>
            <StartPAOS xmlns="urn:iso:std:iso-iec:24727:tech:schema">
                <SessionIdentifier>a471704b-aca2-4e74-b14e-f7cace664122</SessionIdentifier>
                <ConnectionHandle xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ConnectionHandleType">
                    <CardApplication>e80704007f00070302</CardApplication>
                    <SlotHandle>00</SlotHandle>
                </ConnectionHandle>
                <UserAgent>
                    <Name>AusweisApp2</Name>
                    <VersionMajor>2</VersionMajor>
                    <VersionMinor>2</VersionMinor>
                    <VersionSubminor>2</VersionSubminor>
                </UserAgent>
                <SupportedAPIVersions>
                    <Major>1</Major>
                    <Minor>1</Minor>
                    <Subminor>5</Subminor>
                </SupportedAPIVersions>
            </StartPAOS>
        </soap:Body>
    </soap:Envelope>
    """;

  private static final String SOAP_MESSAGE_WITH_NO_MESSAGE_ID = """
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:paos="urn:liberty:paos:2006-08" xmlns:wsa="http://www.w3.org/2005/03/addressing" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1" xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
        <soap:Header>
            <paos:PAOS soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next">
                <paos:Version>urn:liberty:paos:2006-08</paos:Version>
                <paos:EndpointReference>
                    <paos:Address>http://www.projectliberty.org/2006/01/role/paos</paos:Address>
                    <paos:MetaData>
                        <paos:ServiceType>http://www.bsi.bund.de/ecard/api/1.1/PAOS/GetNextCommand</paos:ServiceType>
                    </paos:MetaData>
                </paos:EndpointReference>
            </paos:PAOS>
            <wsa:ReplyTo>
                <wsa:Address>http://www.projectliberty.org/2006/02/role/paos</wsa:Address>
            </wsa:ReplyTo>
        </soap:Header>
        <soap:Body>
            <StartPAOS xmlns="urn:iso:std:iso-iec:24727:tech:schema">
                <SessionIdentifier>a471704b-aca2-4e74-b14e-f7cace664122</SessionIdentifier>
                <ConnectionHandle xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ConnectionHandleType">
                    <CardApplication>e80704007f00070302</CardApplication>
                    <SlotHandle>00</SlotHandle>
                </ConnectionHandle>
                <UserAgent>
                    <Name>AusweisApp2</Name>
                    <VersionMajor>2</VersionMajor>
                    <VersionMinor>2</VersionMinor>
                    <VersionSubminor>2</VersionSubminor>
                </UserAgent>
                <SupportedAPIVersions>
                    <Major>1</Major>
                    <Minor>1</Minor>
                    <Subminor>5</Subminor>
                </SupportedAPIVersions>
            </StartPAOS>
        </soap:Body>
    </soap:Envelope>
    """;


  private static final String SOAP_MESSAGE_WITH_MESSAGE_ID_ELMENT_AND_CHILD_HAS_MESSAGE_ID_ELEMENT = """
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:paos="urn:liberty:paos:2006-08" xmlns:wsa="http://www.w3.org/2005/03/addressing" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1" xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
        <soap:Header>
            <paos:PAOS soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next">
                <paos:Version>urn:liberty:paos:2006-08</paos:Version>
                <paos:EndpointReference>
                    <paos:Address>http://www.projectliberty.org/2006/01/role/paos</paos:Address>
                    <paos:MetaData>
                        <paos:ServiceType>http://www.bsi.bund.de/ecard/api/1.1/PAOS/GetNextCommand</paos:ServiceType>
                    </paos:MetaData>
                </paos:EndpointReference>
            </paos:PAOS>
            <wsa:ReplyTo>
                <wsa:Address>http://www.projectliberty.org/2006/02/role/paos</wsa:Address>
                <wsa:MessageID>childMessageID</wsa:MessageID>
            </wsa:ReplyTo>
            <wsa:MessageID>urn:uuid:5f8dd8ff-83bd-efb1-d339-f86ca6303acf</wsa:MessageID>
        </soap:Header>
        <soap:Body>
            <StartPAOS xmlns="urn:iso:std:iso-iec:24727:tech:schema">
                <SessionIdentifier>a471704b-aca2-4e74-b14e-f7cace664122</SessionIdentifier>
                <ConnectionHandle xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ConnectionHandleType">
                    <CardApplication>e80704007f00070302</CardApplication>
                    <SlotHandle>00</SlotHandle>
                </ConnectionHandle>
                <UserAgent>
                    <Name>AusweisApp2</Name>
                    <VersionMajor>2</VersionMajor>
                    <VersionMinor>2</VersionMinor>
                    <VersionSubminor>2</VersionSubminor>
                </UserAgent>
                <SupportedAPIVersions>
                    <Major>1</Major>
                    <Minor>1</Minor>
                    <Subminor>5</Subminor>
                </SupportedAPIVersions>
            </StartPAOS>
        </soap:Body>
    </soap:Envelope>
    """;

  private static final String SOAP_MESSAGE_ONLY_CHILD_HAS_MESSAGE_ID_ELEMENT = """
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:paos="urn:liberty:paos:2006-08" xmlns:wsa="http://www.w3.org/2005/03/addressing" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ecard="http://www.bsi.bund.de/ecard/api/1.1" xmlns:iso="urn:iso:std:iso-iec:24727:tech:schema">
        <soap:Header>
            <paos:PAOS soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next">
                <paos:Version>urn:liberty:paos:2006-08</paos:Version>
                <paos:EndpointReference>
                    <paos:Address>http://www.projectliberty.org/2006/01/role/paos</paos:Address>
                    <paos:MetaData>
                        <paos:ServiceType>http://www.bsi.bund.de/ecard/api/1.1/PAOS/GetNextCommand</paos:ServiceType>
                    </paos:MetaData>
                </paos:EndpointReference>
            </paos:PAOS>
            <wsa:ReplyTo>
                <wsa:Address>http://www.projectliberty.org/2006/02/role/paos</wsa:Address>
                <wsa:MessageID>childMessageID</wsa:MessageID>
            </wsa:ReplyTo>
        </soap:Header>
        <soap:Body>
            <StartPAOS xmlns="urn:iso:std:iso-iec:24727:tech:schema">
                <SessionIdentifier>a471704b-aca2-4e74-b14e-f7cace664122</SessionIdentifier>
                <ConnectionHandle xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ConnectionHandleType">
                    <CardApplication>e80704007f00070302</CardApplication>
                    <SlotHandle>00</SlotHandle>
                </ConnectionHandle>
                <UserAgent>
                    <Name>AusweisApp2</Name>
                    <VersionMajor>2</VersionMajor>
                    <VersionMinor>2</VersionMinor>
                    <VersionSubminor>2</VersionSubminor>
                </UserAgent>
                <SupportedAPIVersions>
                    <Major>1</Major>
                    <Minor>1</Minor>
                    <Subminor>5</Subminor>
                </SupportedAPIVersions>
            </StartPAOS>
        </soap:Body>
    </soap:Envelope>
    """;



  @Test
  void testGetHeaderElementWhenChildElementHasMessageElement() throws Exception
  {
    InputStream inputStream = new ByteArrayInputStream(SOAP_MESSAGE_WITH_MESSAGE_ID.getBytes());
    SOAPMessage message = MessageFactory.newInstance().createMessage(new MimeHeaders(), inputStream);
    String messageID = Util.getHeaderValue(message, "http://www.w3.org/2005/03/addressing", "MessageID");
    Assertions.assertEquals("urn:uuid:5f8dd8ff-83bd-efb1-d339-f86ca6303acf", messageID);
  }

  @Test
  void testGetHeaderElementWhenChildElementHasNoMessageId() throws Exception
  {
    InputStream inputStream = new ByteArrayInputStream(SOAP_MESSAGE_WITH_NO_MESSAGE_ID.getBytes());
    SOAPMessage message = MessageFactory.newInstance().createMessage(new MimeHeaders(), inputStream);
    String messageID = Util.getHeaderValue(message, "http://www.w3.org/2005/03/addressing", "MessageID");
    Assertions.assertNull(messageID);
  }

  @Test
  void testGetHeaderElementWhenChildElementHasElementMessageId() throws Exception
  {
    InputStream inputStream = new ByteArrayInputStream(SOAP_MESSAGE_WITH_MESSAGE_ID_ELMENT_AND_CHILD_HAS_MESSAGE_ID_ELEMENT.getBytes());
    SOAPMessage message = MessageFactory.newInstance().createMessage(new MimeHeaders(), inputStream);
    String messageID = Util.getHeaderValue(message, "http://www.w3.org/2005/03/addressing", "MessageID");
    Assertions.assertEquals("urn:uuid:5f8dd8ff-83bd-efb1-d339-f86ca6303acf", messageID);
  }

  @Test
  void testGetHeaderElementWhenOnylChildElementHasNoMessageId() throws Exception
  {
    InputStream inputStream = new ByteArrayInputStream(SOAP_MESSAGE_ONLY_CHILD_HAS_MESSAGE_ID_ELEMENT.getBytes());
    SOAPMessage message = MessageFactory.newInstance().createMessage(new MimeHeaders(), inputStream);
    String messageID = Util.getHeaderValue(message, "http://www.w3.org/2005/03/addressing", "MessageID");
    Assertions.assertNull(messageID);
  }
}
