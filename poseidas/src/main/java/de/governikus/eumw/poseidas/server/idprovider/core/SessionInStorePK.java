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

import java.io.Serializable;
import java.util.Objects;

import jakarta.persistence.Embeddable;


/**
 * Primary key of a {@link SessionInStore} .
 *
 * @author mehrtens
 */
@Embeddable
public class SessionInStorePK implements Serializable
{

  private static final long serialVersionUID = 1L;

  private String sessionId;

  private String className;

  /**
   * totally senseless constructor for JPA, do not use!
   */
  public SessionInStorePK()
  {
    // object is nonsense now
  }

  /**
   * Creates a new primary key.
   *
   * @param sessionId The unique id of this session
   * @param className the class name of this session
   */
  SessionInStorePK(String sessionId, String className)
  {
    this.sessionId = sessionId;
    this.className = className;
  }

  /**
   * return ID of the session
   */
  public String getSessionId()
  {
    return sessionId;
  }


  @Override
  public int hashCode()
  {
    return Objects.hashCode(className) * 2 + Objects.hashCode(sessionId);
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
    SessionInStorePK other = (SessionInStorePK)obj;
    return Objects.equals(className, other.className) && Objects.equals(sessionId, other.sessionId);
  }
}
