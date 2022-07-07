/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware.entities;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;

import de.governikus.eumw.eidasstarterkit.EidasRequest;
import de.governikus.eumw.eidasstarterkit.EidasRequestSectorType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


/**
 * Just a holder class for a request from a provider
 */
@Getter
@NoArgsConstructor
@Entity
public class RequestSession
{

  @Id
  private String reqId;

  private String relayState;

  private String reqDestination;

  private String reqProviderName;

  private String reqProviderEntityId;

  private Instant creationTime;

  @Setter
  @Column(unique = true)
  private String eidRef;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable
  private Map<String, Boolean> requestedAttributes;


  public RequestSession(String relayState, EidasRequest eidasRequest)
  {
    this.relayState = relayState;
    this.reqId = eidasRequest.getId();
    this.reqDestination = eidasRequest.getDestination();
    this.reqProviderEntityId = eidasRequest.getIssuer();
    this.creationTime = Instant.now();
    this.requestedAttributes = new HashMap<>();
    this.reqProviderName = eidasRequest.getSectorType() == EidasRequestSectorType.PRIVATE
      ? eidasRequest.getProviderName() : null;
    eidasRequest.getRequestedAttributes()
                .forEach(entry -> requestedAttributes.put(entry.getKey().getValue(), entry.getValue()));
  }

}
