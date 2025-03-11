/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

import jakarta.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCodeWithResponseException;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasmiddleware.handler.RequestHandler;
import de.governikus.eumw.eidasmiddleware.handler.ResponseHandler;
import de.governikus.eumw.eidasstarterkit.EidasLoaEnum;
import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Receive the incoming SAML requests
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER)
@RequiredArgsConstructor
public class RequestReceiver
{

  private final RequestHandler requestHandler;

  private final ResponseHandler responseHandler;

  private final ConfigurationService configurationService;

  /**
   * This endpoint accepts incoming SAML requests using the SAML redirect binding protocol. The endpoint can also be
   * used to switch the language.
   */
  @GetMapping
  public ModelAndView doGet(@RequestParam(required = false, name = HttpRedirectUtils.RELAYSTATE_PARAMNAME) String relayState,
                            @RequestParam(required = false, name = HttpRedirectUtils.REQUEST_PARAMNAME) String samlRequestBase64,
                            @RequestParam(required = false, name = HttpRedirectUtils.SIGALG_PARAMNAME) String sigAlg,
                            @RequestParam(required = false, name = HttpRedirectUtils.SIGVALUE_PARAMNAME) String signature,
                            @RequestParam(required = false, name = "sessionId") String sessionId,
                            @RequestHeader(required = false, name = "User-Agent") String userAgent,
                            HttpSession httpSession)
  {
    // in case this parameter is present this is a SAML authn request
    if (StringUtil.notNullOrEmpty(samlRequestBase64))
    {
      try
      {
        EidasRequest eidasRequest = requestHandler.handleSAMLRedirectRequest(samlRequestBase64,
                                                                             relayState,
                                                                             sigAlg,
                                                                             signature);
        httpSession.setAttribute(eidasRequest.getId(), new ResponseSender.SamlResponseRecord(null, null, null));
        // httpSession.setAttribute(SESSION_ID, eidasRequest.getId());
        return handleEIDASRequest(eidasRequest, relayState, userAgent, httpSession);
      }
      catch (ErrorCodeWithResponseException e)
      {
        Arrays.stream(e.getDetails()).forEach(log::warn);
        log.debug(e.getMessage(), e);
        return showSamlErrorPage(e, relayState, httpSession);
      }
      catch (RequestProcessingException e)
      {
        log.debug("There was an error while processing the request", e);
        return showErrorPage(e.getMessage());
      }
    }
    // in case this parameter is present the user already sent the SAML authn request and is now switching the
    // language
    else if (StringUtil.notNullOrEmpty(sessionId))
    {
      return showMiddlewarePage(sessionId, userAgent);
    }
    // in case neither the saml request nor the sessionId parameter is present this is an invalid request
    else
    {
      return showErrorPage("Either parameter SAMLRequest or sessionId must be present");
    }
  }

  /**
   * This endpoint accepts the incoming SAML request using the SAML POST binding
   */
  @PostMapping
  public ModelAndView doPost(@RequestParam(required = false, name = HttpRedirectUtils.RELAYSTATE_PARAMNAME) String relayState,
                             @RequestParam(HttpRedirectUtils.REQUEST_PARAMNAME) String samlRequestBase64,
                             @RequestHeader(required = false, name = "User-Agent") String userAgent,
                             HttpSession httpSession)
  {
    try
    {
      EidasRequest eidasRequest = requestHandler.handleSAMLPostRequest(relayState, samlRequestBase64);
      httpSession.setAttribute(eidasRequest.getId(), new ResponseSender.SamlResponseRecord(null, null, null));
      return handleEIDASRequest(eidasRequest, relayState, userAgent, httpSession);
    }
    catch (ErrorCodeWithResponseException e)
    {
      Arrays.stream(e.getDetails()).forEach(log::warn);
      log.debug(e.getMessage(), e);
      return showSamlErrorPage(e, relayState, httpSession);
    }
    catch (RequestProcessingException e)
    {
      log.debug("There was an error while processing the request", e);
      return showErrorPage(e.getMessage());
    }
  }

  private ModelAndView handleEIDASRequest(EidasRequest request,
                                          String relayState,
                                          String userAgent,
                                          HttpSession httpSession)
  {
    if (EidasLoaEnum.LOA_TEST.equals(request.getAuthClassRef()))
    {
      String samlResponse = responseHandler.prepareDummyResponse(request.getId(), request.getTestCase());
      // To ensure that the language can be changed on the response view we have to override the samlResponseRecord
      // object in the http session
      ResponseSender.SamlResponseRecord samlResponseRecord = new ResponseSender.SamlResponseRecord(samlResponse,
                                                                                                   responseHandler.getConsumerURLForRequestID(request.getId()),
                                                                                                   relayState);
      httpSession.setAttribute(request.getId(), samlResponseRecord);
      return createResponseView(samlResponseRecord.relayState(),
                                samlResponse,
                                samlResponseRecord.consumerURL(),
                                request.getId());
    }
    return showMiddlewarePage(request.getId(), userAgent);
  }

  private ModelAndView createResponseView(String relayState,
                                          String samlResponse,
                                          String consumerURLForRequestID,
                                          String authnRequestId)
  {
    ModelAndView response = new ModelAndView("response");
    response.addObject("SAML", samlResponse);
    response.addObject("consumerURL", consumerURLForRequestID);
    response.addObject("relayState", relayState);
    response.addObject("authnRequestId", authnRequestId);
    response.addObject("linkToSelf", ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER);
    return response;
  }

  /**
   * Return thymeleaf error view in case there were any errors
   */
  private ModelAndView showErrorPage(String errorMessage)
  {
    ModelAndView error = new ModelAndView("error");
    if (errorMessage != null)
    {
      error.addObject("errorMessage", errorMessage);
    }
    error.setStatus(HttpStatus.BAD_REQUEST);
    return error;
  }

  /**
   * Show the middleware page where the user can start the AusweisApp.
   *
   * @param sessionId The sessionId that is returned by {@link RequestHandler#handleSAMLPostRequest(String, String)} or
   *          {@link RequestHandler#handleSAMLRedirectRequest(String, String, String, String)}
   * @param userAgent to redirect the user the correct way to AusweisApp
   * @return The ModelAndView object that represents the thymeleaf view
   */
  private ModelAndView showMiddlewarePage(String sessionId, String userAgent)
  {
      String ausweisappLink;
      if (isMobileDevice(userAgent))
      {
        ausweisappLink = "eid://127.0.0.1:24727/eID-Client?tcTokenURL=";
      }
      else
      {
        ausweisappLink = "http://127.0.0.1:24727/eID-Client?tcTokenURL=";
      }
      ModelAndView modelAndView = new ModelAndView("middleware");

      String tcTokenURL = requestHandler.getTcTokenURL(sessionId);
      modelAndView.addObject("tcTokenURL", tcTokenURL);

      ausweisappLink = ausweisappLink.concat(URLEncoder.encode(tcTokenURL, StandardCharsets.UTF_8));
      modelAndView.addObject("ausweisapp", ausweisappLink);

      String linkToSelf = ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER + "?sessionId=" + sessionId;
      modelAndView.addObject("linkToSelf", linkToSelf);
      return modelAndView;
    }

    private ModelAndView showSamlErrorPage(ErrorCodeWithResponseException e, String relayState, HttpSession httpSession)
  {
    RequestingServiceProvider reqSP = configurationService.getProviderByEntityID(e.getIssuer());
    String samlResponse = responseHandler.prepareSAMLErrorResponse(reqSP,
                                                                   e.getRequestId(),
                                                                   e.getCode(),
                                                                   e.getDetails());
    ResponseSender.SamlResponseRecord samlResponseRecord = new ResponseSender.SamlResponseRecord(samlResponse,
                                                                                                 reqSP.getAssertionConsumerURL(),
                                                                                                 relayState);
    httpSession.setAttribute(e.getRequestId(), samlResponseRecord);
    return createResponseView(relayState, samlResponse, reqSP.getAssertionConsumerURL(), e.getRequestId());
  }

  private boolean isMobileDevice(String userAgentHeader)
  {
    if (StringUtils.isBlank(userAgentHeader))
    {
      return false;
    }
    String userAgent = userAgentHeader.toLowerCase(Locale.ENGLISH);
    boolean comesFromMobileDevice = false;
    if (userAgent.contains("iphone") || userAgent.contains("android") || userAgent.contains("ipod")
        || userAgent.contains("ipad"))
    {
      comesFromMobileDevice = true;
    }
    return comesFromMobileDevice;
  }
}
