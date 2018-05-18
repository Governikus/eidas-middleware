/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.util.HashMap;
import java.util.Map;

import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;



/**
 * Just a holder class for a request from a provider
 * 
 * @author hohnholt
 */
public class RequestSession
{

  private String relayState;

  private String reqId;

  private String reqDestination;

  private final Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();

  RequestSession(String relayState, String reqId, String reqDestination)
  {
    super();
    this.relayState = relayState;
    this.reqId = reqId;
    this.reqDestination = reqDestination;
  }

  public RequestSession(String relayState, EidasRequest eidasRequest)
  {
    this(relayState, eidasRequest.getId(), eidasRequest.getDestination());
    this.requestedAttributes.putAll(eidasRequest.getRequestedAttributesMap());
  }

  public String getRelayState()
  {
    return relayState;
  }

  public void setRelayState(String relayState)
  {
    this.relayState = relayState;
  }

  public String getReqId()
  {
    return reqId;
  }

  public void setReqId(String reqId)
  {
    this.reqId = reqId;
  }

  public String getReqDestination()
  {
    return reqDestination;
  }

  public void setReqDestination(String reqDestination)
  {
    this.reqDestination = reqDestination;
  }

  public Map<EidasPersonAttributes, Boolean> getRequestedAttributes()
  {
    return requestedAttributes;
  }
}
