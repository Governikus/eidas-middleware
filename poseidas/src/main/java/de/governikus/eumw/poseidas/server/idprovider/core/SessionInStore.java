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

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.NamedQuery;


/**
 * Stores the Session in the database.
 *
 * @author mehrtens
 */
@Entity
@NamedQuery(name = "getNumberEntries", query = "SELECT COUNT(s.creationTime) FROM SessionInStore s")
@NamedQuery(name = "getOldEntries", query = "SELECT s FROM SessionInStore s WHERE s.creationTime < :creationTime")
@NamedQuery(name = "getAllForClass", query = "SELECT s FROM SessionInStore s WHERE s.key.className = :className")
@NamedQuery(name = "getByRequestId", query = "SELECT s FROM SessionInStore s WHERE s.key.className = :className AND s.requestId = :requestId")
public class SessionInStore implements Serializable
{

  private static final long serialVersionUID = 1L;

  @Id
  private final SessionInStorePK key;

  @Lob
  private StoreableSession storedSession;

  private long creationTime;

  private String requestId;

  /**
   * Create new instance. Usually that instance will be saved several times after session content has changed.
   *
   * @param key
   * @param session
   * @param creationTime
   * @param requestId
   */
  SessionInStore(SessionInStorePK key, StoreableSession session, long creationTime, String requestId)
  {
    this.key = key;
    this.storedSession = session;
    this.creationTime = creationTime;
    this.requestId = requestId;
  }

  /**
   * Just for JPA
   */
  public SessionInStore()
  {
    key = null;
  }

  /**
   * Return the id of the session.
   */
  public SessionInStorePK getKey()
  {
    return key;
  }

  /**
   * return the whole session object
   */
  public StoreableSession getSession()
  {
    return storedSession;
  }

  /**
   * set session object after its content has changed
   */
  public void setSession(StoreableSession session)
  {
    this.storedSession = session;
  }

  /**
   * return creation time of session to indicate out-dated sessions
   */
  public long getCreationTime()
  {
    return creationTime;
  }

  public String getRequestId()
  {
    return requestId;
  }
}
