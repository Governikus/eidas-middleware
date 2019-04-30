/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasmiddleware.ConfigHolder;
import de.governikus.eumw.eidasmiddleware.RequestSession;
import de.governikus.eumw.eidasmiddleware.ServiceProviderConfig;
import de.governikus.eumw.eidasmiddleware.SessionStore;
import de.governikus.eumw.eidasmiddleware.WebServiceHelper;
import de.governikus.eumw.eidasmiddleware.eid.HttpServerUtils;
import de.governikus.eumw.eidasmiddleware.eid.RequestingServiceProvider;
import de.governikus.eumw.eidasstarterkit.EidasLoA;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.EidasResponse;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.eidservice.EIDRequestInput;
import de.governikus.eumw.poseidas.server.eidservice.EIDRequestResponse;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;


@Slf4j
@Controller
@RequestMapping(ContextPaths.EIDAS_CONTEXT_PATH + ContextPaths.TC_TOKEN)
public class TcToken
{

  private final SessionStore store;

  private final ConfigHolder configHolder;

  private final ServiceProviderConfig serviceProviderConfig;

  @Autowired
  private HSMServiceHolder hsmServiceHolder;

  public TcToken(SessionStore store, ConfigHolder configHolder, ServiceProviderConfig serviceProviderConfig)
  {
    this.store = store;
    this.configHolder = configHolder;
    this.serviceProviderConfig = serviceProviderConfig;
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

    String lastErrorMessage = null;
    Exception lastException = null;
    try
    {
      tcTokenResponse(resp, samlReqSession);
    }
    catch (IOException e)
    {
      lastErrorMessage = "cannot create tc token response";
      lastException = e;
    }
    catch (GeneralSecurityException e)
    {
      lastErrorMessage = "cannot connect EID Service";
      log.error(lastErrorMessage, e);
      lastException = e;
    }
    catch (ResultMajorException e)
    {
      lastErrorMessage = e.getMessage();
      lastException = e;
    }
    if (StringUtil.notNullOrEmpty(lastErrorMessage))
    {
      log.warn("lastException: " + lastException);
      log.warn("Error in request from provider with  ConsumerServiceURL "
               + samlReqSession.getReqDestination());
      log.warn("Request id " + samlReqSession.getReqId());
      RequestingServiceProvider reqSP = serviceProviderConfig.getProviderByEntityID(samlReqSession.getReqProviderEntityId());
      sendSAMLErrorMsg(resp, reqSP, samlReqSession, ErrorCode.EID_ERROR, lastErrorMessage);
    }
  }

  /**
   * Generate the TCToken and write it to the response.
   *
   * @param response
   * @param reqParser
   * @throws IOException
   * @throws GeneralSecurityException
   */
  protected void tcTokenResponse(HttpServletResponse response, RequestSession reqParser)
    throws IOException, GeneralSecurityException
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    ServiceProviderDto provider = config.getServiceProvider()
                                        .get(reqParser.getReqProviderName() == null
                                          ? configHolder.getEntityIDInt() : reqParser.getReqProviderName());

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
            log.warn("UNKNOWN Authrequest Attribute");
            break;
        }
      }
      else
      {
        log.warn("UNKNOWN Authrequest Attribute");
      }
    }

    EIDRequestResponse eidResult = EIDInternal.getInstance().useID(intRequest, provider);

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

  private void sendSAMLErrorMsg(HttpServletResponse response,
                                RequestingServiceProvider reqSP,
                                RequestSession samlReqSession,
                                ErrorCode error,
                                String... msg)
  {
    log.warn(error.toDescription(msg));
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    EidasSigner signer;
    try
    {
      signer = getEidasSigner();
      EidasResponse rsp = new EidasResponse(reqSP.getAssertionConsumerURL(), reqSP.getEntityID(), null,
                                            samlReqSession.getReqId(),
                                            configHolder.getServerURLWithContextPath()
                                                                       + ContextPaths.METADATA,
                                            EidasLoA.HIGH, signer, null);
      byte[] eidasResp = rsp.generateErrorRsp(error, msg);
      String content = WebServiceHelper.createForwardToConsumer(eidasResp,
                                                                samlReqSession.getRelayState().orElse(null),
                                                                null);
      HttpServerUtils.setPostContent(content, reqSP.getAssertionConsumerURL(), null, response);
    }
    catch (IOException | GeneralSecurityException | XMLParserException | UnmarshallingException
      | MarshallingException | SignatureException | TransformerFactoryConfigurationError
      | TransformerException | ComponentInitializationException e)
    {
      log.warn(e.getMessage(), e);
      try
      {
        response.getWriter().write(Utils.createErrorMessage("internal error in sendSAMLErrorMsg"));
      }
      catch (IOException e1)
      {
        log.warn(e1.getMessage(), e1);
      }
    }
  }

  private EidasSigner getEidasSigner() throws UnrecoverableKeyException, KeyStoreException,
    NoSuchAlgorithmException, IOException, GeneralSecurityException
  {
    EidasSigner signer;
    if (hsmServiceHolder.getKeyStore() == null)
    {
      signer = new EidasSigner(true, configHolder.getAppSignatureKeyPair().getKey(),
                               configHolder.getAppSignatureKeyPair().getCert());
    }
    else
    {
      signer = new EidasSigner(hsmServiceHolder.getKeyStore());
    }
    return signer;
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
