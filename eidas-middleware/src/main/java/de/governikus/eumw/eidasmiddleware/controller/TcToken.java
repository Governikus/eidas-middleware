/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map.Entry;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.WebServiceHelper;
import de.governikus.eumw.eidasmiddleware.entities.RequestSession;
import de.governikus.eumw.eidasmiddleware.repositories.RequestSessionRepository;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.eidservice.EIDRequestInput;
import de.governikus.eumw.poseidas.server.eidservice.EIDRequestResponse;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.exceptions.InvalidConfigurationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.TC_TOKEN)
@RequiredArgsConstructor
public class TcToken
{

  private final RequestSessionRepository requestSessionRepository;

  private final ConfigurationService configurationService;

  private final EIDInternal eidInternal;


  /**
   * Show an HTML page containing the errorMessage <br>
   * NOTE: Do not show an error message that could leak user input to prevent XXE attacks
   *
   * @param resp The {@link HttpServletResponse} to send the HTML response
   * @param errorMessage The error message to be shown.
   */
  private void displayHTMLErrorMessage(HttpServletResponse resp, String errorMessage)
  {
    try
    {
      resp.getWriter().write(Utils.createErrorMessage(errorMessage));
    }
    catch (IOException e)
    {
      resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      log.error(e.getMessage(), e);
    }
  }

  @GetMapping
  public void doGet(@RequestParam("sessionID") String sessionID, HttpServletResponse resp)
  {
    if (sessionID == null)
    {
      // status code 400 should be set in case of new eID activation in TR-03130
      // version 2.0 and above.
      String errormessage = "no SessionID";
      resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      log.warn(errormessage);
      displayHTMLErrorMessage(resp, errormessage);
      return;
    }

    RequestSession samlReqSession = null;
    try
    {
      samlReqSession = requestSessionRepository.getById(sessionID);
    }
    catch (Exception e)
    {
      log.error("can not access DB for entry " + sessionID, e);
    }

    if (samlReqSession == null)
    {
      // status code 400 should be set in case of new eID activation in TR-03130
      // version 2.0 and above.
      String errormessage = "no SessionObject found for this session";
      resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      log.warn("no SessionObject found for this session: {}", sessionID);
      displayHTMLErrorMessage(resp, errormessage);
      return;
    }
    try
    {
      tcTokenResponse(resp, samlReqSession);
    }
    catch (IOException e)
    {
      log.error("cannot create tc token response", e);
    }
    catch (ResultMajorException | InvalidConfigurationException e)
    {
      log.error(e.getMessage(), e);
    }
  }

  /**
   * Generate the TCToken and write it to the response.
   *
   * @param response
   * @param reqParser
   * @throws IOException
   */
  protected void tcTokenResponse(HttpServletResponse response, RequestSession reqParser)
    throws IOException, InvalidConfigurationException
  {
    EidasMiddlewareConfig configuration = configurationService.getConfiguration()
                                                              .orElseThrow(() -> new ResultMajorException("Cannot get configuration"));

    EIDRequestInput intRequest = new EIDRequestInput(true);

    for ( Entry<String, Boolean> entry : reqParser.getRequestedAttributes().entrySet() )
    {
      EidasNaturalPersonAttributes eidasNaturalPersonAttribute = null;
      try
      {
        eidasNaturalPersonAttribute = EidasNaturalPersonAttributes.getValueOf(entry.getKey());
      }
      catch (ErrorCodeException e)
      {
        log.warn("UNKNOWN Authrequest Attribute: '{}'", eidasNaturalPersonAttribute);
        continue;
      }
      switch (eidasNaturalPersonAttribute)
      {
        case FIRST_NAME:
          intRequest.addRequiredFields(EIDKeys.GIVEN_NAMES);
          break;

        case FAMILY_NAME:
          intRequest.addRequiredFields(EIDKeys.FAMILY_NAMES);
          break;

        case BIRTH_NAME:
          intRequest.addRequiredFields(EIDKeys.BIRTH_NAME);
          intRequest.addRequiredFields(EIDKeys.FAMILY_NAMES);
          intRequest.addRequiredFields(EIDKeys.GIVEN_NAMES);
          break;

        case DATE_OF_BIRTH:
          intRequest.addRequiredFields(EIDKeys.DATE_OF_BIRTH);
          break;

        case PLACE_OF_BIRTH:
          intRequest.addRequiredFields(EIDKeys.PLACE_OF_BIRTH);
          break;

        case CURRENT_ADDRESS:
          intRequest.addOptionalFields(EIDKeys.PLACE_OF_RESIDENCE);
          break;

        case PERSON_IDENTIFIER:
          intRequest.addRequiredFields(EIDKeys.RESTRICTED_ID);
          break;

        case NATIONALITY:
          intRequest.addOptionalFields(EIDKeys.NATIONALITY);
          break;

        default:
          log.warn("UNKNOWN Authrequest Attribute: '{}'", eidasNaturalPersonAttribute);
          break;
      }
    }

    var publicServiceProviderName = configuration.getEidasConfiguration().getPublicServiceProviderName();
    var spName = reqParser.getReqProviderName() == null ? publicServiceProviderName : reqParser.getReqProviderName();
    ServiceProviderType provider = configuration.getEidConfiguration()
                                                .getServiceProvider()
                                                .stream()
                                                .filter(sp -> sp.getName().equals(spName))
                                                .findFirst()
                                                .orElseThrow(() -> new ResultMajorException("Cannot get service provider from config with name "
                                                                                            + spName));
    EIDRequestResponse eidResult = eidInternal.useID(intRequest, provider);

    String refID = URLEncoder.encode(eidResult.getRequestId(), StandardCharsets.UTF_8);

    reqParser.setEidRef(refID);
    requestSessionRepository.save(reqParser);

    if (!eidResult.getResultMajor().equals(Constants.EID_MAJOR_OK))
    {
      String errorMessage = "Error while requesting attributes. <br/>Major result: " + eidResult.getResultMajor()
                            + " <br/>Minor result: " + eidResult.getResultMinor()
                            + (eidResult.getResultMessage() == null ? ""
                              : " <br/>Result message: " + eidResult.getResultMessage());
      log.error(errorMessage);
      throw new ResultMajorException(errorMessage);
    }

    String eIDPSKId = eidResult.getSessionId();

    response.setContentType("text/xml");
    response.setCharacterEncoding("utf-8");
    response.getWriter()
            .write(Utils.readFromStream(WebServiceHelper.class.getResourceAsStream("tcTokenAttached.xml"))
                        .replace("#{PAOS_RECEIVER_URL}",
                                 configurationService.getServerURLWithEidasContextPath() + ContextPaths.PAOS_SERVLET)
                        .replace("#{SESSIONID}", eIDPSKId)
                        .replace("#{REFRESH_ADDRESS}",
                                 configurationService.getServerURLWithEidasContextPath() + ContextPaths.RESPONSE_SENDER
                                                       + "?refID=" + refID));
  }

  private static class ResultMajorException extends RuntimeException
  {

    private static final long serialVersionUID = 1L;

    public ResultMajorException(String errorMessage)
    {
      super(errorMessage);
    }

  }
}
