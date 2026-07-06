package de.governikus.eumw.poseidas.server.pki.caserviceaccess;

import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.ConditionalCertificateDescription;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.ConditionalCertificateSeqType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificateDescriptionRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificateDescriptionResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesDescriptionReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetCertificatesReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetPKICommunicationCertRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetPKICommunicationCertResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.GetPKICommunicationCertReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestCertificateRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestCertificateResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestCertificateReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestPKICommunicationCertRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestPKICommunicationCertResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.RequestPKICommunicationCertReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendRSCCertRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendRSCCertResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendRSCCertReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendeIDServerCertsRequest;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendeIDServerCertsResult;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.SendeIDServerCertsReturnCodeType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.TerminalAuthWebService_1_4_0;
import de.governikus.eumw.utils.xml.XmlHelper;


@ExtendWith(MockitoExtension.class)
class TermAuthServiceTest
{


  public static final URL schemaUrl = RestrictedIdService140Test.class.getResource("/META-INF/wsdl/CA-Services-1-4-0/part-3/termAuth/BasicTypes_DV_TerminalAuth.xsd");

  @Mock
  PKIServiceConnector connector;

  @Mock
  TerminalAuthWebService_1_4_0 port;

  private TermAuthService termAuthService;

  @BeforeEach
  void setUp() throws Exception
  {
    termAuthService = new TermAuthService(connector, "https://riURL");
    termAuthService.setPort(port);
  }

  @Test
  void testGetCACertificatesSchemaConformance()
  {
    Mockito.when(port.getCertificates(Mockito.any(GetCertificatesRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      GetCertificatesResult getCertificatesResult = new GetCertificatesResult();
      getCertificatesResult.setReturnCode(GetCertificatesReturnCodeType.OK_CERT_AVAILABLE);
      ConditionalCertificateSeqType conditionalCertificateSeqType = new ConditionalCertificateSeqType();
      conditionalCertificateSeqType.getCertificate().add("cert".getBytes(StandardCharsets.UTF_8));
      getCertificatesResult.setCertificateSeq(conditionalCertificateSeqType);
      return getCertificatesResult;
    });
    Assertions.assertDoesNotThrow(() -> termAuthService.getCACertificates());
  }

  @Test
  void testRequestCertificateSchemaConformance()
  {
    Mockito.when(port.requestCertificate(Mockito.any(RequestCertificateRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      RequestCertificateResult requestCertificateResult = new RequestCertificateResult();
      requestCertificateResult.setReturnCode(RequestCertificateReturnCodeType.OK_CERT_AVAILABLE);
      ConditionalCertificateSeqType conditionalCertificateSeqType = new ConditionalCertificateSeqType();
      conditionalCertificateSeqType.getCertificate()
                                   .add(TermAuthServiceTest.class.getResourceAsStream("/terminalCertificates/terminalCert.cvc")
                                                                 .readAllBytes());
      requestCertificateResult.setCertificateSeq(conditionalCertificateSeqType);
      return requestCertificateResult;
    });
    Assertions.assertDoesNotThrow(() -> termAuthService.requestCertificate("request".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void testGetCertificateDescriptionSchemaConformance()
  {
    Mockito.when(port.getCertificateDescription(Mockito.any(GetCertificateDescriptionRequest.class)))
           .thenAnswer(invocation -> {
             String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
             XmlHelper.validateWithSchema(requestString, schemaUrl);
             GetCertificateDescriptionResult getCertificateDescriptionResult = new GetCertificateDescriptionResult();
             getCertificateDescriptionResult.setReturnCode(GetCertificatesDescriptionReturnCodeType.OK_RECEIVED_CORRECTLY);
             ConditionalCertificateDescription conditionalCertificateDescription = new ConditionalCertificateDescription();
             conditionalCertificateDescription.setCertificateDescription("cert".getBytes(StandardCharsets.UTF_8));
             getCertificateDescriptionResult.setCertificateDescription(conditionalCertificateDescription);
             return getCertificateDescriptionResult;
           });
    Assertions.assertDoesNotThrow(() -> termAuthService.getCertificateDescription("hash".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void testSendeIDServerCertsSchemaConformance()
  {
    Mockito.when(port.sendeIDServerCerts(Mockito.any(SendeIDServerCertsRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      SendeIDServerCertsResult sendeIDServerCertsResult = new SendeIDServerCertsResult();
      sendeIDServerCertsResult.setReturnCode(SendeIDServerCertsReturnCodeType.OK_ENTANGLEMENT_SUCCESSFUL);
      return sendeIDServerCertsResult;
    });
    Assertions.assertDoesNotThrow(() -> termAuthService.sendeIDServerCerts("cmsData".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void testUpdateRscSchemaConformance()
  {
    Mockito.when(port.sendRSCCert(Mockito.any(SendRSCCertRequest.class))).thenAnswer(invocation -> {
      String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
      XmlHelper.validateWithSchema(requestString, schemaUrl);
      SendRSCCertResult sendRSCCertResult = new SendRSCCertResult();
      sendRSCCertResult.setReturnCode(SendRSCCertReturnCodeType.OK_RECEIVED_CORRECTLY);
      return sendRSCCertResult;
    });
    Assertions.assertDoesNotThrow(() -> termAuthService.updateRsc("cmsData".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void testRequestNewTlsSchemaConformance()
  {
    Mockito.when(port.requestPKICommunicationCert(Mockito.any(RequestPKICommunicationCertRequest.class)))
           .thenAnswer(invocation -> {
             String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
             XmlHelper.validateWithSchema(requestString, schemaUrl);
             RequestPKICommunicationCertResult requestPKICommunicationCertResult = new RequestPKICommunicationCertResult();
             requestPKICommunicationCertResult.setReturnCode(RequestPKICommunicationCertReturnCodeType.OK_RECEIVED_CORRECTLY);
             return requestPKICommunicationCertResult;
           });
    Assertions.assertDoesNotThrow(() -> termAuthService.requestNewTls("cmsData".getBytes(StandardCharsets.UTF_8),
                                                                      "messageid"));
  }

  @Test
  void testTryFetchNewTlsSchemaConformance()
  {
    Mockito.when(port.getPKICommunicationCert(Mockito.any(GetPKICommunicationCertRequest.class)))
           .thenAnswer(invocation -> {
             String requestString = XmlHelper.marshalObject(invocation.getArgument(0));
             XmlHelper.validateWithSchema(requestString, schemaUrl);
             GetPKICommunicationCertResult getPKICommunicationCertResult = new GetPKICommunicationCertResult();
             getPKICommunicationCertResult.setReturnCode(GetPKICommunicationCertReturnCodeType.OK_CERT_AVAILABLE);
             return getPKICommunicationCertResult;
           });
    Assertions.assertDoesNotThrow(() -> termAuthService.tryFetchNewTls("messageid"));
  }
}
