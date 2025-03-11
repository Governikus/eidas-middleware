/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.controller;

import java.io.Serial;
import java.io.Serializable;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.handler.ResponseHandler;
import lombok.extern.slf4j.Slf4j;


/**
 * Create the SAML response and send it to the eIDAS connector using the user's browser
 */
@Slf4j
@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER)
public class ResponseSender
{

  private static final String REF_ID = "refID";

  public static final String MISSING_SESSION_ERROR_MESSAGE = """
    We could not find an existing session for this authentication process.
    The eIDAS Middleware requires cookies to work correctly.
    Also make sure you do not switch browsers after the interaction with the AusweisApp.""";

  private final ResponseHandler responseHandler;

  /**
   * @see HttpServlet#HttpServlet()
   */
  public ResponseSender(ResponseHandler responseHandler)
  {
    this.responseHandler = responseHandler;
  }

  /**
   * This endpoint is called after the AusweisApp has finished the communication with the eID and redirects the user's
   * browser to this endpoint
   */
  @GetMapping
  public ModelAndView doGet(@RequestParam(REF_ID) String refID, HttpSession httpSession)
  {
    if (refID == null)
    {
      // status code 400 should be set in case of new eID activation in TR-03130
      // version 2.0 and above.
      String errormessage = "Required parameter refID missing";
      log.warn(errormessage);
      ModelAndView error = new ModelAndView("error");
      error.addObject("errorMessage", errormessage);
      return error;
    }

    if (httpSession == null || httpSession.isNew())
    {
      log.warn("Received a request without a session for refID {}", refID);
      ModelAndView error = new ModelAndView("error");
      error.addObject("errorMessage", MISSING_SESSION_ERROR_MESSAGE);
      return error;
    }

    try
    {
      String authnRequestId = responseHandler.getAuthnRequestIdForRefId(refID);
      if (httpSession.getAttribute(authnRequestId) == null)
      {
        throw new RequestProcessingException(MISSING_SESSION_ERROR_MESSAGE);
      }

      String samlResponse = responseHandler.getResultForRefID(refID);

      SamlResponseRecord samlResponseRecord = new SamlResponseRecord(samlResponse,
                                                                     responseHandler.getConsumerURLForRefID(refID),
                                                                     responseHandler.getRelayStateForRefID(refID));
      ModelAndView response = getResponseModelAndView(samlResponseRecord, authnRequestId);
      httpSession.setAttribute(authnRequestId, samlResponseRecord);
      return response;
    }
    catch (RequestProcessingException e)
    {
      ModelAndView error = new ModelAndView("error");
      error.addObject("errorMessage", e.getMessage());
      log.error("Error creating saml response: ", e);
      return error;
    }
  }

  /**
   * This endpoint is used to switch the language.
   *
   */
  @PostMapping
  public ModelAndView switchLanguage(@RequestParam(name = "authnRequestId") String authnRequestId,
                                     HttpSession httpSession)
  {
    if (httpSession == null || httpSession.isNew() || httpSession.getAttribute(authnRequestId) == null)
    {
      log.warn("Received a request without a session");
      ModelAndView error = new ModelAndView("error");
      error.addObject("errorMessage", MISSING_SESSION_ERROR_MESSAGE);
      return error;
    }
    SamlResponseRecord samlResponseRecord = (SamlResponseRecord)httpSession.getAttribute(authnRequestId);
    return getResponseModelAndView(samlResponseRecord, authnRequestId);
  }

  private ModelAndView getResponseModelAndView(SamlResponseRecord samlResponseRecord, String authnRequestId)
  {
    ModelAndView response = new ModelAndView("response");
    response.addObject("SAML", samlResponseRecord.samlResponse);
    response.addObject("consumerURL", samlResponseRecord.consumerURL);
    response.addObject("relayState", samlResponseRecord.relayState);
    response.addObject("authnRequestId", authnRequestId);
    response.addObject("linkToSelf", ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER);
    return response;
  }

  public record SamlResponseRecord(String samlResponse, String consumerURL, String relayState) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
  }
}
