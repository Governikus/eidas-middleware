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

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasmiddleware.RequestSession;
import de.governikus.eumw.eidasmiddleware.SessionStore;
import de.governikus.eumw.eidasmiddleware.WebServiceHelper;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.eidservice.EIDRequestInput;
import de.governikus.eumw.poseidas.server.eidservice.EIDRequestResponse;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.TC_TOKEN)
public class TcToken
{

  private final SessionStore store;

  private final ConfigHolder configHolder;

  private final EIDInternal eidInternal;

  public TcToken(SessionStore store, ConfigHolder configHolder, EIDInternal eidInternal)
  {
    this.store = store;
    this.configHolder = configHolder;
    this.eidInternal = eidInternal;
  }

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
      samlReqSession = store.getById(sessionID);
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
    catch (ResultMajorException e)
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
  protected void tcTokenResponse(HttpServletResponse response, RequestSession reqParser) throws IOException
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();

    EIDRequestInput intRequest = new EIDRequestInput(true);
    intRequest.setConfig(config);

    for ( Entry<EidasPersonAttributes, Boolean> entry : reqParser.getRequestedAttributes().entrySet() )
    {
      if (entry.getKey() instanceof EidasNaturalPersonAttributes)
      {
        EidasNaturalPersonAttributes key = (EidasNaturalPersonAttributes)entry.getKey();
        switch (key)
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

          default:
            log.warn("UNKNOWN Authrequest Attribute: '{}'", key);
            break;
        }
      }
      else
      {
        log.warn("UNKNOWN Authrequest Attribute: '{}'", entry.getKey());
      }
    }

    ServiceProviderDto provider = config.getServiceProvider()
                                        .get(reqParser.getReqProviderName() == null
                                          ? configHolder.getEntityIDInt() : reqParser.getReqProviderName());
    if (provider == null)
    {
      log.error("Cannot get service provider from config with name {}", reqParser.getReqProviderName());
    }

    EIDRequestResponse eidResult = eidInternal.useID(intRequest, provider);

    String refID = URLEncoder.encode(eidResult.getRequestId(), "UTF-8");

    try
    {
      store.update(reqParser.getReqId(), refID);
    }
    catch (Exception e)
    {
      log.error("CAN NOT UPDATE DB for entry " + reqParser.getReqId(), e);
    }

    if (!eidResult.getResultMajor().equals(Constants.EID_MAJOR_OK))
    {
      String errorMessage = "Error while requesting attributes. <br/>Major result: "
                            + eidResult.getResultMajor() + " <br/>Minor result: " + eidResult.getResultMinor()
                            + (eidResult.getResultMessage() == null ? ""
                              : " <br/>Result message: " + eidResult.getResultMessage());
      log.error(errorMessage);
      throw new ResultMajorException(errorMessage);
    }

    String eIDPSKId = eidResult.getSessionId();
    String paosReceiverURL = eidResult.getECardServerAddress();

    response.setContentType("text/xml");
    response.setCharacterEncoding("utf-8");
    response.getWriter()
            .write(Utils.readFromStream(WebServiceHelper.class.getResourceAsStream("tcTokenAttached.xml"))
                        .replace("#{PAOS_RECEIVER_URL}", paosReceiverURL)
                        .replace("#{SESSIONID}", eIDPSKId)
                        .replace("#{REFRESH_ADDRESS}",
                                 configHolder.getServerURLWithContextPath() + ContextPaths.RESPONSE_SENDER
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
