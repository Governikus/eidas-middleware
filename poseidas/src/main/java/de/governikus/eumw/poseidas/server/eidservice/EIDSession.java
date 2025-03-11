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

import java.util.Map;

import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResult;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer.EIDStatus;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import de.governikus.eumw.poseidas.server.idprovider.core.StoreableSession;

import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * Session inside the eID-Server which links the POAS conversation to the getResult-, and useID requests
 *
 * @author tt
 */
public class EIDSession implements StoreableSession
{

  private static final long serialVersionUID = 10L;

  private Integer sequenceNumber = null;

  private Result result;

  private Map<EIDKeys, EIDInfoResult> infoMap;

  private final long creationTime;

  private final String requestId;

  private final String sessionId;

  private SessionInput sessionInput;

  // Set to failed on default to only indicate success explicitly
  private EIDStatus status = EIDStatus.FAILED;

  private final String logPrefix;

  EIDSession(String sessionId, String requestId, String providerName)
  {
    this.sessionId = sessionId;
    this.requestId = requestId;
    creationTime = System.currentTimeMillis();

    StringBuilder builder = new StringBuilder();
    if (providerName == null)
    {
      builder.append("<unknown>: ");
    }
    else
    {
      builder.append(providerName);
      builder.append(": ");
    }
    if (requestId == null)
    {
      builder.append("<unknown>: ");
    }
    else
    {
      builder.append(requestId);
      builder.append(": ");
    }
    logPrefix = builder.toString();
  }

  void setSequenceNumber(int sequenceNumber)
  {
    this.sequenceNumber = sequenceNumber;
  }

  Result getResult()
  {
    return result;
  }

  void setResult(Result container)
  {
    this.result = container;
  }

  /**
   * This contains the attributes read form the nPA.
   */
  Map<EIDKeys, EIDInfoResult> getInfoMap()
  {
    return infoMap;
  }

  void setInfoMap(Map<EIDKeys, EIDInfoResult> infoMap)
  {
    this.infoMap = infoMap;
  }

  Integer getSequenceNumber()
  {
    return sequenceNumber;
  }

  @Override
  public long getCreationTime()
  {
    return creationTime;
  }

  @Override
  public String getSessionId()
  {
    return sessionId;
  }

  @Override
  public String getRequestId()
  {
    return requestId;
  }

  @Override
  public void removed(boolean cleanup)
  {
    // Nothing to do
  }

  public void setSessionInput(SessionInput sessionInput)
  {
    this.sessionInput = sessionInput;
  }

  public SessionInput getSessionInput()
  {
    return sessionInput;
  }

  public void setStatus(EIDStatus status)
  {
    this.status = status;
  }

  public EIDStatus getStatus()
  {
    return status;
  }


  public String getLogPrefix()
  {
    return logPrefix;
  }
}
