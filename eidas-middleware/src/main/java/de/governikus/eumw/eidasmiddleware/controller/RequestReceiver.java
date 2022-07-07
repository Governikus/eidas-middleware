/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.controller;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.HttpRedirectUtils;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.handler.RequestHandler;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import lombok.extern.slf4j.Slf4j;


/**
 * Receive the incoming SAML requests
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER)
public class RequestReceiver
{

  private final RequestHandler requestHandler;

  public RequestReceiver(RequestHandler requestHandler)
  {
    this.requestHandler = requestHandler;
  }

  /**
   * This endpoint accepts incoming SAML requests using the SAML redirect binding protocol. The endpoint can also be
   * used to switch the language.
   */
  @GetMapping
  public ModelAndView doGet(@RequestParam(required = false, name = HttpRedirectUtils.RELAYSTATE_PARAMNAME) String relayState,
                            @RequestParam(required = false, name = HttpRedirectUtils.REQUEST_PARAMNAME) String samlRequestBase64,
                            @RequestParam(required = false, name = "sessionId") String sessionId,
                            @RequestHeader(required = false, name = "User-Agent") String userAgent)
  {
    // in case this parameter is present this is a SAML authn request
    if (StringUtil.notNullOrEmpty(samlRequestBase64))
    {
      String createdSessionId;
      try
      {
        createdSessionId = requestHandler.handleSAMLRequest(relayState, samlRequestBase64, false);
      }
      catch (RequestProcessingException e)
      {
        log.debug("There was an error while processing the request", e);
        return showErrorPage(e.getMessage());
      }
      return new ModelAndView("redirect:" + ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER
                              + "?sessionId=" + createdSessionId);
    }
    // in case this parameter is present the user already sent the SAML authn request and is now switching the
    // language
    else if (StringUtil.notNullOrEmpty(sessionId))
    {
      return showMiddlewarePage(sessionId, userAgent);
    }
    // in case neither the samlrequest nor the sessionId parameter is present this is an invalid request
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
                             @RequestHeader(required = false, name = "User-Agent") String userAgent)
  {
    try
    {
      String sessionId = requestHandler.handleSAMLRequest(relayState, samlRequestBase64, true);
      return new ModelAndView("redirect:" + ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER
                              + "?sessionId=" + sessionId);
    }
    catch (RequestProcessingException e)
    {
      log.debug("There was an error while processing the request", e);
      return showErrorPage(e.getMessage());
    }
  }

  /**
   * Return thymeleaf error view in case the were any errors
   */
  private ModelAndView showErrorPage(String errorMessage)
  {
    ModelAndView error = new ModelAndView("error");
    if (errorMessage != null)
    {
      error.addObject("errorMessage", errorMessage);
    }
    return error;
  }

  /**
   * Show the middleware page where the user can start the AusweisApp2.
   *
   * @param sessionId The sessionId that is returned by
   *          {@link RequestHandler#handleSAMLRequest(String, String, boolean)}
   * @param userAgent to redirect the user the correct way to AusweisApp2
   * @return The ModelAndView object that represents the thymeleaf view
   */
  private ModelAndView showMiddlewarePage(String sessionId, String userAgent)
  {
    try
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
      ausweisappLink = ausweisappLink.concat(URLEncoder.encode(requestHandler.getTcTokenURL(sessionId),
                                                               StandardCharsets.UTF_8.name()));
      ModelAndView modelAndView = new ModelAndView("middleware");
      modelAndView.addObject("ausweisapp", ausweisappLink);

      String linkToSelf = ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.REQUEST_RECEIVER + "?sessionId=" + sessionId;
      modelAndView.addObject("linkToSelf", linkToSelf);
      return modelAndView;
    }
    catch (UnsupportedEncodingException e)
    {
      return showErrorPage(e.getMessage());
    }
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
