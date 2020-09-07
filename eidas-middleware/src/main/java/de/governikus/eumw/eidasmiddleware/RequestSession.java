/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.util.Optional;

import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasRequestSectorType;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;
import lombok.Getter;



/**
 * Just a holder class for a request from a provider
 *
 * @author hohnholt
 */
@Getter
public class RequestSession
{

  private String relayState;

  private String reqId;

  private String reqDestination;

  private String reqProviderName;

  private String reqProviderEntityId;

  private final Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();

  RequestSession(String relayState,
                 String reqId,
                 String reqDestination,
                 String reqProviderName,
                 String reqProviderEntityId)
  {
    super();
    this.relayState = relayState;
    this.reqId = reqId;
    this.reqDestination = reqDestination;
    this.reqProviderName = reqProviderName;
    this.reqProviderEntityId = reqProviderEntityId;
  }


  public RequestSession(String reqId,
                        String reqDestination,
                        String reqProviderName,
                        String reqProviderEntityId)
  {
    this(null, reqId, reqDestination, reqProviderName, reqProviderEntityId);
  }

  public RequestSession(String relayState, EidasRequest eidasRequest)
  {
    this(relayState, eidasRequest.getId(), eidasRequest.getDestination(), getReqProviderName(eidasRequest),
         eidasRequest.getIssuer());
    this.requestedAttributes.putAll(eidasRequest.getRequestedAttributesMap());
  }

  private static String getReqProviderName(EidasRequest eidasRequest)
  {
    if (eidasRequest.getSectorType() == EidasRequestSectorType.PRIVATE)
    {
      if (eidasRequest.getRequesterId() != null)
      {
        return eidasRequest.getRequesterId();
      }
      if (eidasRequest.getProviderName() != null)
      {
        return eidasRequest.getProviderName();
      }
    }
    return null;
  }

  public RequestSession(EidasRequest eidasRequest)
  {
    this(null, eidasRequest);
  }

  public Optional<String> getRelayState()
  {
    return Optional.ofNullable(relayState);
  }

}
