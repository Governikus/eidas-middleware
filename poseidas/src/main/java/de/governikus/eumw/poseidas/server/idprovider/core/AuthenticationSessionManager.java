/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.core;

import de.governikus.eumw.eidascommon.ErrorCodeException;



/**
 * This class manages the authentication sessions. It stores the sessions somewhere and returns them if any
 * user requests them.
 *
 * @author mehrtens
 */
public final class AuthenticationSessionManager
{

  private static final AuthenticationSessionManager INSTANCE = new AuthenticationSessionManager();

  /**
   * Get the only instance in this VM. Set system variable
   * de.governikus.eumw.poseidas.server.idprovider.core.AuthenticationSessionManager.useDatabase <strong>
   * before </strong> accessing this class to specify whether the sessions are kept im memory or in database.
   */
  public static AuthenticationSessionManager getInstance()
  {
    return INSTANCE;
  }

  private SessionStoreAO sessionStoreFacade;

  private AuthenticationSessionManager()
  {
    sessionStoreFacade = new SessionStoreAOBeanMemory();
  }

  /**
   * Stores the session into some sort of storage. A database or somewhere in the memory.
   *
   * @param session
   * @throws ErrorCodeException
   */
  public void store(StoreableSession session) throws ErrorCodeException
  {
    sessionStoreFacade.storeSession(session);
  }

  /**
   * Returns the session from the storage.
   *
   * @param sessionId sessionID to search for.
   * @param type The class the session to get is from.
   */
  public <T extends StoreableSession> T get(String sessionId, Class<T> type)
  {
    return sessionStoreFacade.getSession(sessionId, type);
  }

  /**
   * Returns the session from the storage by the request ID.
   *
   * @param requestId requestId to search for.
   * @param type The class the session to get is from.
   */
  public <T extends StoreableSession> T getByRequestId(String requestId, Class<T> type)
  {
    return sessionStoreFacade.getSessionByRequestId(requestId, type);
  }

  /**
   * Remove a session and its request id from internal storage. Call this method also in case the session
   * itself was not stored to remove the request id.
   *
   * @param session the session to remove, <code>null</code> permitted and resulting in no operation.
   */
  public void remove(StoreableSession session)
  {
    if (session != null)
    {
      sessionStoreFacade.removeSession(session);
      session.removed(false);
    }
  }

  /**
   * Triggers a clean up of the stored session. Old sessions will be removed. A cleanup is also triggered from
   * time to time when a new session is stored. Clients are not requested to call this method.
   *
   * @return The number of sessions stored after running cleanup.
   * @throws ErrorCodeException
   */
  public long getNumberSessions()
  {
    return sessionStoreFacade.getNumberSessions();
  }

  public void setMaxPendingRequests(int maxPendingRequests)
  {
    sessionStoreFacade.setMaxPendingRequests(maxPendingRequests);
  }

}
