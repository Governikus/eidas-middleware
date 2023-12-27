/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.core;

import java.util.Objects;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;


/**
 * Stores the request IDs already used in the database.
 *
 * @author mehrtens
 */
@Entity
public class RequestIdStore
{

  @Id
  private String requestId;

  /**
   * Only needed for JPA.
   */
  public RequestIdStore()
  {
    // Nothing to do
  }

  /**
   * create immutable instance
   *
   * @param requestId
   */
  RequestIdStore(String requestId)
  {
    this.requestId = requestId;
  }

  /**
   * return id of a SAML request seen lately
   */
  public String getRequestId()
  {
    return requestId;
  }

  @Override
  public int hashCode()
  {
    return Objects.hashCode(requestId);
  }

  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (obj == null || getClass() != obj.getClass())
    {
      return false;
    }
    RequestIdStore other = (RequestIdStore)obj;
    return Objects.equals(requestId, other.requestId);
  }
}
