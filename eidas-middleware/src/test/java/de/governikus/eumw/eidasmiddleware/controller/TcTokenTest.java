package de.governikus.eumw.eidasmiddleware.controller;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;

import de.governikus.eumw.eidasmiddleware.entities.RequestSession;
import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.eidservice.EIDRequestResponse;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationTestHelper;


@ExtendWith(MockitoExtension.class)
class TcTokenTest
{

  private static final String SESSION_ID = "session-id";

  private static final String REQUEST_ID = "request-id";

  @Mock
  private RequestSessionRepository requestSessionRepository;

  @Mock
  private ConfigurationService configurationService;

  @Mock
  private EIDInternal eidInternal;

  @Test
  void doGetWithValidSessionIDReturnsTcToken() throws Exception
  {
    TcToken token = new TcToken(requestSessionRepository, configurationService, eidInternal);

    RequestSession mockSession = Mockito.mock(RequestSession.class);

    Mockito.when(requestSessionRepository.getReferenceById(SESSION_ID)).thenReturn(mockSession);

    Mockito.when(mockSession.getReqProviderName()).thenReturn(ConfigurationTestHelper.SP_NAME);

    Mockito.when(configurationService.getConfiguration())
           .thenReturn(Optional.of(ConfigurationTestHelper.createValidConfiguration()));

    Mockito.when(configurationService.getServerURLWithEidasContextPath())
           .thenReturn("http://serverURL/eidas-middleware");

    Mockito.when(mockSession.getRequestedAttributes())
           .thenReturn(Map.of(EidasNaturalPersonAttributes.BIRTH_NAME.getName(), true));

    EIDRequestResponse eidRequestResponse = Mockito.mock(EIDRequestResponse.class);

    Mockito.when(eidInternal.useID(Mockito.any(), Mockito.any())).thenReturn(eidRequestResponse);

    Mockito.when(eidRequestResponse.getRequestId()).thenReturn(REQUEST_ID);
    Mockito.when(eidRequestResponse.getResultMajor()).thenReturn(ResultMajor.OK.toString());
    Mockito.when(eidRequestResponse.getSessionId()).thenReturn(SESSION_ID);

    MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
    token.doGet(SESSION_ID, mockHttpServletResponse);

    Assertions.assertEquals(200, mockHttpServletResponse.getStatus());
    String contentAsString = mockHttpServletResponse.getContentAsString();
    Assertions.assertTrue(contentAsString.contains("""
      <TCTokenType>
          <ServerAddress>http://serverURL/eidas-middleware/paosreceiver</ServerAddress>
          <SessionIdentifier>session-id</SessionIdentifier>
          <RefreshAddress>http://serverURL/eidas-middleware/ResponseSender?refID=request-id</RefreshAddress>
          <Binding>urn:liberty:paos:2006-08</Binding>
      </TCTokenType>"""));
  }

  @Test
  void testDoGetWithNoSessionIdReturnsBadRequest()
  {
    TcToken token = new TcToken(requestSessionRepository, configurationService, eidInternal);

    MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
    token.doGet(null, mockHttpServletResponse);
    Assertions.assertEquals(400, mockHttpServletResponse.getStatus());
  }

  @Test
  void testDoGetWithSessionIdNotFoundReturnsBadRequest()
  {
    TcToken token = new TcToken(requestSessionRepository, configurationService, eidInternal);
    Mockito.when(requestSessionRepository.getReferenceById(SESSION_ID)).thenReturn(null);

    MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
    token.doGet(SESSION_ID, mockHttpServletResponse);
    Assertions.assertEquals(400, mockHttpServletResponse.getStatus());
  }

  @Test
  void testDoGetWithEmptyConfigurationReturnsServerError()
  {
    TcToken token = new TcToken(requestSessionRepository, configurationService, eidInternal);
    RequestSession mockSession = Mockito.mock(RequestSession.class);
    Mockito.when(requestSessionRepository.getReferenceById(SESSION_ID)).thenReturn(mockSession);
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.empty());

    MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
    token.doGet(SESSION_ID, mockHttpServletResponse);
    Assertions.assertEquals(500, mockHttpServletResponse.getStatus());
  }

  @Test
  void testDoGetWithResultMajorNotOkReturnsBadRequest() throws Exception
  {
    TcToken token = new TcToken(requestSessionRepository, configurationService, eidInternal);

    RequestSession mockSession = Mockito.mock(RequestSession.class);

    Mockito.when(requestSessionRepository.getReferenceById(SESSION_ID)).thenReturn(mockSession);

    Mockito.when(mockSession.getReqProviderName()).thenReturn(ConfigurationTestHelper.SP_NAME);

    Mockito.when(configurationService.getConfiguration())
           .thenReturn(Optional.of(ConfigurationTestHelper.createValidConfiguration()));

    Mockito.when(mockSession.getRequestedAttributes())
           .thenReturn(Map.of(EidasNaturalPersonAttributes.BIRTH_NAME.getName(), true));

    EIDRequestResponse eidRequestResponse = Mockito.mock(EIDRequestResponse.class);

    Mockito.when(eidInternal.useID(Mockito.any(), Mockito.any())).thenReturn(eidRequestResponse);

    Mockito.when(eidRequestResponse.getRequestId()).thenReturn(REQUEST_ID);
    Mockito.when(eidRequestResponse.getResultMajor()).thenReturn(ResultMajor.ERROR.toString());
    Mockito.when(eidRequestResponse.getResultMinor()).thenReturn(ResultMinor.COMMON_INTERNAL_ERROR.toString());
    Mockito.when(eidRequestResponse.getResultMessage()).thenReturn("Internal Error");

    MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
    token.doGet(SESSION_ID, mockHttpServletResponse);
    Assertions.assertEquals(500, mockHttpServletResponse.getStatus());
  }
}
