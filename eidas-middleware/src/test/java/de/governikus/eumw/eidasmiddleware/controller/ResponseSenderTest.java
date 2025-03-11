package de.governikus.eumw.eidasmiddleware.controller;

import static de.governikus.eumw.eidasmiddleware.controller.ResponseSender.MISSING_SESSION_ERROR_MESSAGE;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.ui.ModelMap;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidasmiddleware.handler.ResponseHandler;


@ExtendWith(MockitoExtension.class)
class ResponseSenderTest
{

  private static final String DUMMY_REF_ID = "dummyRefID";

  private static final String DUMMY_SAML_RESPONSE = "dummySamlResponse";

  private static final String DUMMY_AUTHN_REQUEST_ID = "DummyAuthnRequestId";

  @Mock
  private ResponseHandler responseHandler;

  private ResponseSender responseSender;

  @BeforeEach
  void setUp()
  {
    responseSender = new ResponseSender(responseHandler);
  }

  @Test
  void testDoGetWithoutRefIdReturnsErrorView()
  {
    ModelAndView modelAndView = responseSender.doGet(null, null);
    Assertions.assertEquals("error", modelAndView.getViewName());
    ModelMap modelMap = modelAndView.getModelMap();
    Assertions.assertEquals(1, modelMap.size());
    Assertions.assertEquals("Required parameter refID missing", modelMap.get("errorMessage"));
  }

  @Test
  void testDoGetWithoutHttpSessionReturnsErrorView()
  {
    ModelAndView modelAndView = responseSender.doGet(DUMMY_REF_ID, null);
    Assertions.assertEquals("error", modelAndView.getViewName());
    ModelMap modelMap = modelAndView.getModelMap();
    Assertions.assertEquals(1, modelMap.size());
    Assertions.assertEquals(MISSING_SESSION_ERROR_MESSAGE, modelMap.get("errorMessage"));
  }

  @Test
  void testDoGetWithNewHttpSessionReturnsErrorView()
  {
    MockHttpSession httpSession = new MockHttpSession();
    httpSession.setNew(true);
    ModelAndView modelAndView = responseSender.doGet(DUMMY_REF_ID, httpSession);
    Assertions.assertEquals("error", modelAndView.getViewName());
    ModelMap modelMap = modelAndView.getModelMap();
    Assertions.assertEquals(1, modelMap.size());
    Assertions.assertEquals(MISSING_SESSION_ERROR_MESSAGE, modelMap.get("errorMessage"));
  }

  @Test
  void testDoGetAndHttpSessionHasNoAuthnRequestIdReturnsErrorView()
  {
    MockHttpSession httpSession = new MockHttpSession();
    httpSession.setNew(false);
    Mockito.when(responseHandler.getAuthnRequestIdForRefId(DUMMY_REF_ID)).thenReturn(DUMMY_AUTHN_REQUEST_ID);
    ModelAndView modelAndView = responseSender.doGet(DUMMY_REF_ID, httpSession);
    Assertions.assertEquals("error", modelAndView.getViewName());
    ModelMap modelMap = modelAndView.getModelMap();
    Assertions.assertEquals(1, modelMap.size());
    Assertions.assertEquals(MISSING_SESSION_ERROR_MESSAGE, modelMap.get("errorMessage"));
  }

  @Test
  void testDoGetAndHttpSessionHasAuthnRequestId()
  {
    MockHttpSession httpSession = new MockHttpSession();
    httpSession.setNew(false);
    httpSession.setAttribute(DUMMY_AUTHN_REQUEST_ID, new ResponseSender.SamlResponseRecord(null, null, null));
    Mockito.when(responseHandler.getAuthnRequestIdForRefId(DUMMY_REF_ID)).thenReturn(DUMMY_AUTHN_REQUEST_ID);
    Mockito.when(responseHandler.getResultForRefID(DUMMY_REF_ID)).thenReturn(DUMMY_SAML_RESPONSE);
    Mockito.when(responseHandler.getConsumerURLForRefID(DUMMY_REF_ID)).thenReturn("dummyURL");
    Mockito.when(responseHandler.getRelayStateForRefID(DUMMY_REF_ID)).thenReturn("dummyRelayState");
    ModelAndView modelAndView = responseSender.doGet(DUMMY_REF_ID, httpSession);

    Assertions.assertNotNull(httpSession.getAttribute(DUMMY_AUTHN_REQUEST_ID));
    Assertions.assertEquals("response", modelAndView.getViewName());
    ModelMap modelMap = modelAndView.getModelMap();
    Assertions.assertEquals(5, modelMap.size());
    Assertions.assertEquals(DUMMY_SAML_RESPONSE, modelMap.get("SAML"));
    Assertions.assertEquals("dummyURL", modelMap.get("consumerURL"));
    Assertions.assertEquals("dummyRelayState", modelMap.get("relayState"));
    Assertions.assertEquals(DUMMY_AUTHN_REQUEST_ID, modelMap.get("authnRequestId"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER, modelMap.get("linkToSelf"));
  }

  @Test
  void testDoPostSwitchingLanguage()
  {
    MockHttpSession httpSession = new MockHttpSession();
    httpSession.setNew(false);
    httpSession.setAttribute(DUMMY_REF_ID,
                             new ResponseSender.SamlResponseRecord(DUMMY_SAML_RESPONSE, "dummyURL", "dummyRelayState"));
    ModelAndView modelAndView = responseSender.switchLanguage(DUMMY_REF_ID, httpSession);
    Assertions.assertEquals("response", modelAndView.getViewName());
    ModelMap modelMap = modelAndView.getModelMap();
    Assertions.assertEquals(5, modelMap.size());
    Assertions.assertEquals(DUMMY_SAML_RESPONSE, modelMap.get("SAML"));
    Assertions.assertEquals("dummyURL", modelMap.get("consumerURL"));
    Assertions.assertEquals("dummyRelayState", modelMap.get("relayState"));
    Assertions.assertEquals(DUMMY_REF_ID, modelMap.get("authnRequestId"));
    Assertions.assertEquals(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER, modelMap.get("linkToSelf"));
  }

  @Test
  void testDoPostSwitchingLanguageWithNoHttpSessionReturnsErrorView()
  {
    ModelAndView modelAndView = responseSender.switchLanguage(DUMMY_REF_ID, null);
    ModelMap modelMap = modelAndView.getModelMap();
    Assertions.assertEquals(1, modelMap.size());
    Assertions.assertEquals(MISSING_SESSION_ERROR_MESSAGE, modelMap.get("errorMessage"));
  }
}
