/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.controller;

import jakarta.servlet.http.HttpServlet;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidasmiddleware.RequestProcessingException;
import de.governikus.eumw.eidasmiddleware.handler.ResponseHandler;
import de.governikus.eumw.eidasmiddleware.model.ResponseModel;
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

  private final ResponseHandler responseHandler;

  /**
   * @see HttpServlet#HttpServlet()
   */
  public ResponseSender(ResponseHandler responseHandler)
  {
    this.responseHandler = responseHandler;
  }

  /**
   * This endpoint is called after the AusweisApp has finished the communication with the eID and redirects
   * the user's browser to this endpoint
   */
  @GetMapping
  public ModelAndView doGet(@RequestParam(REF_ID) String refID)
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

    try
    {
      String samlResponse = responseHandler.getResultForRefID(refID);

      ModelAndView response = new ModelAndView("response");
      response.addObject("SAML", samlResponse);
      response.addObject("consumerURL", responseHandler.getConsumerURLForRefID(refID));
      response.addObject("relayState", responseHandler.getRelayStateForRefID(refID));
      response.addObject("linkToSelf", ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER);
      response.addObject("responseModel", new ResponseModel());
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
   * @param responseModel The form data that contains the already created SAML response, SAML consumer URL and
   *          SAML relay state
   */
  @PostMapping
  public ModelAndView switchLanguage(@ModelAttribute("responseModel") ResponseModel responseModel)
  {
    ModelAndView response = new ModelAndView("response");
    response.addObject("SAML", responseModel.getSamlResponse());
    response.addObject("consumerURL", responseModel.getConsumerURL());
    response.addObject("relayState", responseModel.getRelayState());
    response.addObject("linkToSelf", ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.RESPONSE_SENDER);
    response.addObject("responseModel", new ResponseModel());
    return response;
  }
}
