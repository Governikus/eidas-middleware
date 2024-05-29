package de.governikus.eumw.eidasmiddleware.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.ui.ModelMap;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeWithResponseException;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasmiddleware.handler.RequestHandler;
import de.governikus.eumw.eidasmiddleware.handler.ResponseHandler;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;


@ExtendWith(MockitoExtension.class)
class RequestReceiverTest
{

  private static final String SAML_REQUEST_BASE_64_MOCK = "samlRequestBase64Mock";

  private static final String REQUEST_ID = "requestId";

  private static final String TC_TOKEN_URL = "https://localhost/TcToken?sessionId=";

  private static final String EID_CLIENT_URL = "http://127.0.0.1:24727/eID-Client?tcTokenURL=";

  private static final String EID_CLIENT_MOBIL_URL = "eid://127.0.0.1:24727/eID-Client?tcTokenURL=";

  private static final String SAML_RESPONSE = "samlResponse";

  private static final String CONSUMER_URL = "consumerUrl";

  private static final String RELAY_STATE = "relayState";

  @Mock
  private RequestHandler requestHandler;

  @Mock
  private ResponseHandler responseHandler;

  @Mock
  private ConfigurationService configurationService;

  @Mock
  private EidasRequest eIDASRequest;

  @Test
  void testDoGetShouldReturnLandingPage() throws Exception
  {
    prepareMocks();
    Mockito.when(requestHandler.getTcTokenURL(REQUEST_ID)).thenReturn(TC_TOKEN_URL + REQUEST_ID);
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView landingPage = requestReceiver.doGet(RELAY_STATE, SAML_REQUEST_BASE_64_MOCK, null, null, null, null);

    Assertions.assertEquals("middleware", landingPage.getViewName());
    ModelMap modelMap = landingPage.getModelMap();
    Assertions.assertEquals(3, modelMap.size());
    Assertions.assertEquals(EID_CLIENT_URL
                            + URLEncoder.encode(TC_TOKEN_URL + REQUEST_ID, StandardCharsets.UTF_8),
                            modelMap.getAttribute("ausweisapp"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER + "?sessionId="
                            + REQUEST_ID,
                            modelMap.getAttribute("linkToSelf"));
  }

  @Test
  void testDoGetWithSessionIdShouldReturnLandingPage() throws Exception
  {
    Mockito.when(requestHandler.getTcTokenURL(REQUEST_ID)).thenReturn(TC_TOKEN_URL + REQUEST_ID);
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView landingPage = requestReceiver.doGet(null, null, null, null, REQUEST_ID, null);

    Mockito.verify(requestHandler, Mockito.never()).handleSAMLPostRequest(Mockito.anyString(), Mockito.anyString());
    Assertions.assertEquals("middleware", landingPage.getViewName());
    ModelMap modelMap = landingPage.getModelMap();
    Assertions.assertEquals(3, modelMap.size());
    Assertions.assertEquals(EID_CLIENT_URL
                            + URLEncoder.encode(TC_TOKEN_URL + REQUEST_ID, StandardCharsets.UTF_8),
                            modelMap.getAttribute("ausweisapp"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER + "?sessionId="
                            + REQUEST_ID,
                            modelMap.getAttribute("linkToSelf"));
  }

  @Test
  void testDoGetShouldReturnResponsePageWhenLoATest() throws Exception
  {
    Mockito.when(requestHandler.handleSAMLRedirectRequest(SAML_REQUEST_BASE_64_MOCK, RELAY_STATE, null, null))
           .thenReturn(eIDASRequest);
    Mockito.when(eIDASRequest.getId()).thenReturn(REQUEST_ID);
    Mockito.when(eIDASRequest.getAuthClassRef()).thenReturn(EidasLoaEnum.LOA_TEST);
    Mockito.when(responseHandler.prepareDummyResponse(REQUEST_ID, null)).thenReturn(SAML_RESPONSE);
    Mockito.when(responseHandler.getConsumerURLForRequestID(REQUEST_ID)).thenReturn(CONSUMER_URL);
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView responsePage = requestReceiver.doGet(RELAY_STATE, SAML_REQUEST_BASE_64_MOCK, null, null, null, null);

    Assertions.assertEquals("response", responsePage.getViewName());
    ModelMap modelMap = responsePage.getModelMap();
    Assertions.assertEquals(5, modelMap.size());
    Assertions.assertEquals(SAML_RESPONSE, modelMap.getAttribute("SAML"));
    Assertions.assertEquals(CONSUMER_URL, modelMap.getAttribute("consumerURL"));
    Assertions.assertEquals(RELAY_STATE, modelMap.getAttribute("relayState"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER,
                            modelMap.getAttribute("linkToSelf"));
    Assertions.assertNotNull(modelMap.getAttribute("responseModel"));
  }

  @Test
  void testDoGetShouldReturnErrorPageWhenSamlRequestAndSessionIdNotPresent() throws Exception
  {
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView errorPage = requestReceiver.doGet(null, null, null, null, null, null);
    Mockito.verify(requestHandler, Mockito.never()).handleSAMLPostRequest(Mockito.anyString(), Mockito.anyString());
    Assertions.assertEquals("error", errorPage.getViewName());
    Assertions.assertEquals("Either parameter SAMLRequest or sessionId must be present",
                            errorPage.getModelMap().getAttribute("errorMessage"));
    Assertions.assertEquals(HttpStatus.BAD_REQUEST, errorPage.getStatus());
  }

  @Test
  void testDoGetShouldReturnErrorResponseWhenErrorCodeWithResponseExceptionIsThrown() throws Exception
  {
    Mockito.when(requestHandler.handleSAMLRedirectRequest(Mockito.anyString(),
                                                          Mockito.anyString(),
                                                          Mockito.isNull(),
                                                          Mockito.isNull()))
           .thenThrow(new ErrorCodeWithResponseException(ErrorCode.SIGNATURE_CHECK_FAILED, "issuer", REQUEST_ID,
                                                         "error Message"));
    RequestingServiceProvider requestingServiceProvider = Mockito.mock(RequestingServiceProvider.class);
    Mockito.when(configurationService.getProviderByEntityID("issuer")).thenReturn(requestingServiceProvider);
    Mockito.when(requestingServiceProvider.getAssertionConsumerURL()).thenReturn("consumerUrl");
    Mockito.when(responseHandler.prepareSAMLErrorResponse(requestingServiceProvider,
                                                          REQUEST_ID,
                                                          ErrorCode.SIGNATURE_CHECK_FAILED,
                                                          "error Message"))
           .thenReturn(SAML_RESPONSE);
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView errorPageWithResponse = requestReceiver.doGet(RELAY_STATE,
                                                               SAML_REQUEST_BASE_64_MOCK,
                                                               null,
                                                               null,
                                                               null,
                                                               null);

    Assertions.assertEquals("response", errorPageWithResponse.getViewName());
    ModelMap modelMap = errorPageWithResponse.getModelMap();
    Assertions.assertEquals(5, modelMap.size());
    Assertions.assertEquals(SAML_RESPONSE, modelMap.getAttribute("SAML"));
    Assertions.assertEquals(CONSUMER_URL, modelMap.getAttribute("consumerURL"));
    Assertions.assertEquals(RELAY_STATE, modelMap.getAttribute("relayState"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER,
                            modelMap.getAttribute("linkToSelf"));
    Assertions.assertNotNull(modelMap.getAttribute("responseModel"));
  }

  @Test
  void testDoGetShouldReturnErrorPageWhenRequestProcessingExceptionIsThrown() throws Exception
  {
    String errorMessage = "Request Processig Exception";
    Mockito.when(requestHandler.handleSAMLRedirectRequest(Mockito.anyString(),
                                                          Mockito.anyString(),
                                                          Mockito.isNull(),
                                                          Mockito.isNull()))
           .thenThrow(new RequestProcessingException(errorMessage));
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView errorPage = requestReceiver.doGet(RELAY_STATE, SAML_REQUEST_BASE_64_MOCK, null, null, null, null);

    Assertions.assertEquals("error", errorPage.getViewName());
    ModelMap modelMap = errorPage.getModelMap();
    Assertions.assertEquals(1, modelMap.size());
    Assertions.assertEquals(errorMessage, modelMap.getAttribute("errorMessage"));
    Assertions.assertEquals(HttpStatus.BAD_REQUEST, errorPage.getStatus());
  }

  @Test
  void testDoPostShouldReturnLandingPage() throws Exception
  {
    prepareMocks();
    Mockito.when(requestHandler.getTcTokenURL(REQUEST_ID)).thenReturn(TC_TOKEN_URL + REQUEST_ID);
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView landingPage = requestReceiver.doPost(RELAY_STATE, SAML_REQUEST_BASE_64_MOCK, "iPhone");

    Assertions.assertEquals("middleware", landingPage.getViewName());
    ModelMap modelMap = landingPage.getModelMap();
    Assertions.assertEquals(3, modelMap.size());
    Assertions.assertEquals(EID_CLIENT_MOBIL_URL
                            + URLEncoder.encode(TC_TOKEN_URL + REQUEST_ID, StandardCharsets.UTF_8),
                            modelMap.getAttribute("ausweisapp"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER + "?sessionId="
                            + REQUEST_ID,
                            modelMap.getAttribute("linkToSelf"));
  }


  @Test
  void testDoPostShouldReturnErrorResponseWhenErrorCodeWithResponseExceptionIsThrown() throws Exception
  {
    Mockito.when(requestHandler.handleSAMLPostRequest(Mockito.anyString(), Mockito.anyString()))
           .thenThrow(new ErrorCodeWithResponseException(ErrorCode.SIGNATURE_CHECK_FAILED, "issuer", REQUEST_ID,
                                                         "error Message"));
    RequestingServiceProvider requestingServiceProvider = Mockito.mock(RequestingServiceProvider.class);
    Mockito.when(configurationService.getProviderByEntityID("issuer")).thenReturn(requestingServiceProvider);
    Mockito.when(requestingServiceProvider.getAssertionConsumerURL()).thenReturn("consumerUrl");
    Mockito.when(responseHandler.prepareSAMLErrorResponse(requestingServiceProvider,
                                                          REQUEST_ID,
                                                          ErrorCode.SIGNATURE_CHECK_FAILED,
                                                          "error Message"))
           .thenReturn(SAML_RESPONSE);
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView errorPageWithResponse = requestReceiver.doPost(RELAY_STATE, SAML_REQUEST_BASE_64_MOCK, null);

    Assertions.assertEquals("response", errorPageWithResponse.getViewName());
    ModelMap modelMap = errorPageWithResponse.getModelMap();
    Assertions.assertEquals(5, modelMap.size());
    Assertions.assertEquals(SAML_RESPONSE, modelMap.getAttribute("SAML"));
    Assertions.assertEquals(CONSUMER_URL, modelMap.getAttribute("consumerURL"));
    Assertions.assertEquals(RELAY_STATE, modelMap.getAttribute("relayState"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER,
                            modelMap.getAttribute("linkToSelf"));
    Assertions.assertNotNull(modelMap.getAttribute("responseModel"));
  }

  @Test
  void testDoPostShouldReturnErrorPageWhenRequestProcessingExceptionIsThrown() throws Exception
  {
    String errorMessage = "Request Processing Exception";
    Mockito.when(requestHandler.handleSAMLPostRequest(Mockito.anyString(), Mockito.anyString()))
           .thenThrow(new RequestProcessingException(errorMessage));
    RequestReceiver requestReceiver = new RequestReceiver(requestHandler, responseHandler, configurationService);
    ModelAndView errorPage = requestReceiver.doPost(RELAY_STATE, SAML_REQUEST_BASE_64_MOCK, null);

    Assertions.assertEquals("error", errorPage.getViewName());
    ModelMap modelMap = errorPage.getModelMap();
    Assertions.assertEquals(1, modelMap.size());
    Assertions.assertEquals(errorMessage, modelMap.getAttribute("errorMessage"));
    Assertions.assertEquals(HttpStatus.BAD_REQUEST, errorPage.getStatus());
  }

  private void prepareMocks() throws ErrorCodeWithResponseException
  {
    Mockito.lenient()
           .when(requestHandler.handleSAMLPostRequest(RELAY_STATE, SAML_REQUEST_BASE_64_MOCK))
           .thenReturn(eIDASRequest);
    Mockito.lenient()
           .when(requestHandler.handleSAMLRedirectRequest(SAML_REQUEST_BASE_64_MOCK, RELAY_STATE, null, null))
           .thenReturn(eIDASRequest);
    Mockito.when(eIDASRequest.getId()).thenReturn(REQUEST_ID);
    Mockito.when(eIDASRequest.getAuthClassRef()).thenReturn(EidasLoaEnum.LOA_HIGH);
  }
}
