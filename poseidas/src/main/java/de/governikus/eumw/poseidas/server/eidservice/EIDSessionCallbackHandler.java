/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.eidservice;

import java.util.Optional;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.Constants;
import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.poseidas.ecardcore.utilities.ECardCoreUtil;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDCallback;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer.EIDStatus;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import de.governikus.eumw.poseidas.server.idprovider.core.AuthenticationSessionManager;

import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * handles the callbacks from the eCard and starts writes the resulting data into the correct session. This
 * class allows using the listener pattern even though the listener objects themselves are serialized into the
 * database.
 *
 * @author hme
 */
public final class EIDSessionCallbackHandler implements ECardIDCallback
{

  private static final long serialVersionUID = 1L;


  private static final Log LOG = LogFactory.getLog(EIDSessionCallbackHandler.class);


  private static EIDSessionCallbackHandler instance = new EIDSessionCallbackHandler();

  private EIDSessionCallbackHandler()
  {
    // Nothing to do
  }

  /**
   * singleton getter
   */
  static EIDSessionCallbackHandler getInstance()
  {
    return instance;
  }

  /**
   * Create a response with given status codes. Called explicitly in error case.
   *
   * @param resultMajor
   * @param resultMinor
   */
  static Result createResult(String resultMajor, String resultMinor, String resultMessage)
  {
    Result result = new Result();
    result.setResultMajor(resultMajor);
    result.setResultMinor(resultMinor);
    if (resultMessage != null)
    {
      result.setResultMessage(ECardCoreUtil.generateInternationalStringType(resultMessage));
    }

    return result;
  }

  /**
   * Handles the Callback. The given eID container is stored in the correct session and the data is handled.
   *
   * @param eIDSessionId
   * @param container
   */
  @Override
  public void seteIDSessionComplete(String eIDSessionId, EIDInfoContainer container)
  {
    EIDSession session = AuthenticationSessionManager.getInstance().get(eIDSessionId, EIDSession.class);
    if (session == null)
    {
      LOG.warn("<unknown>: " + eIDSessionId + ": The Session the callback was for is already removed.");
      return;
    }

    if (container == null)
    {
      LOG.info(session.getLogPrefix()
               + "Something went wrong in the eCardAPI on this server, got null response.");
      session.setResult(createResult(Constants.EID_MAJOR_ERROR,
                                     Constants.EID_MINOR_COMMON_INTERNALERROR,
                                     "Something went wrong in the eCardAPI on this server, got null response."));
    }
    else
    {
      session.setStatus(container.getStatus());
      LOG.info(session.getLogPrefix() + "received response from eCardAPI");
      // Personal Data
      LOG.debug(session.getLogPrefix() + "received response from eCardAPI: " + container.getInfoMap());
      if (container.getStatus() == null)
      {
        session.setResult(createResult(Constants.EID_MAJOR_ERROR,
                                       Constants.EID_MINOR_COMMON_INTERNALERROR,
                                       Optional.ofNullable(container.getResult())
                                               .map(Result::getResultMessage)
                                               .map(InternationalStringType::getValue)
                                               .orElse(null)));
      }
      else if (container.getStatus() == EIDStatus.EXPIRED || container.getStatus() == EIDStatus.REVOKED
               || container.getStatus() == EIDStatus.NOT_AUTHENTIC)
      {
        session.setResult(createResult(Constants.EID_MAJOR_ERROR,
                                       Constants.EID_MINOR_GETRESULT_INVALID_DOCUMENT,
                                       Optional.ofNullable(container.getResult())
                                               .map(Result::getResultMessage)
                                               .map(InternationalStringType::getValue)
                                               .orElse(null)));
      }
      else if (container.hasErrors())
      {
        LOG.warn(session.getLogPrefix() + "result major from eCardAPI: " + container.getResult().getResultMajor());
        LOG.warn(session.getLogPrefix() + "result minor from eCardAPI: " + container.getResult().getResultMinor());
        LOG.warn(session.getLogPrefix() + "result message from eCardAPI: "
                 + (container.getResult().getResultMessage() == null ? "null"
                   : container.getResult().getResultMessage().getValue()));
        session.setResult(container.getResult());
      }
      else
      {
        session.setResult(createResult(Constants.EID_MAJOR_OK, null, null));
      }
      session.setInfoMap(container.getInfoMap());
    }
    try
    {
      AuthenticationSessionManager.getInstance().store(session);
    }
    catch (ErrorCodeException e)
    {
      LOG.error(session.getLogPrefix() + "Can not store session", e);
    }
  }

  @Override
  public SessionInput getSessionInput(String eIDSessionId)
  {
    EIDSession eIDSession = AuthenticationSessionManager.getInstance().get(eIDSessionId, EIDSession.class);
    if (eIDSession == null)
    {
      LOG.warn("The Session the callback was for is already removed.");
      return null;
    }
    if (eIDSession.getResult() != null)
    {
      LOG.warn(eIDSession.getLogPrefix()
               + "This session already has a result, poseidas will not provide a new Session Input");
      return null;
    }
    return eIDSession.getSessionInput();
  }
}
