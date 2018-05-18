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

import java.util.Collection;

import de.governikus.eumw.eidascommon.ErrorCodeException;


/**
 * Interface for AuthenticationSession Storage.
 * 
 * @author mehrtens
 */
public interface SessionStoreAO
{

  /**
   * Returns the session for a given session ID from the storage.
   * 
   * @param sessionId
   * @param type The class the session to get is from.
   */
  <T extends StoreableSession> T getSession(String sessionId, Class<T> type);

  /**
   * Returns the session for a given request ID from the storage.
   * 
   * @param requestId
   * @param type The class the session to get is from.
   */
  <T extends StoreableSession> T getSessionByRequestId(String requestId, Class<T> type);

  /**
   * Stores the session into the storage.
   * 
   * @param session
   * @throws ErrorCodeException
   */
  void storeSession(StoreableSession session) throws ErrorCodeException;

  /**
   * Removes the session and the request ID used for this session from the storage.
   * 
   * @param session, <code>null</code> permitted and resulting in no operation.
   */
  void removeSession(StoreableSession session);

  /**
   * Adds a request ID into the storage.
   * 
   * @param requestID
   * @throws ErrorCodeException thrown in case this id is already in the storage.
   */
  void addRequestId(String requestID) throws ErrorCodeException;

  /**
   * Triggers a clean up of the stored session. Old sessions will be removed. A cleanup is also triggered from
   * time to time when a new session is stored. Clients are not requested to call this method.
   * 
   * @return The number of sessions stored after running cleanup.
   * @throws ErrorCodeException
   */
  long getNumberSessions();

  /**
   * Return a list with all sessions of the given type.
   * 
   * @param type
   */
  <T extends StoreableSession> Collection<T> getAllSessions(Class<T> type);

  void setMaxPendingRequests(int maxPendingRequests);

  /**
   * Number of requests which may be in process before searching for outdated requests.
   */
  int MAX_PENDING_DEFAULT = 200;

  /**
   * If there are too many requests, requests older that 3 minutes may be deleted to avoid database overflow.
   */
  int TIME_LIMIT_HARD_DEFAULT = 3 * 60 * 1000;

  /**
   * When we run the general cleanup all sessions older then 20 minutes will be removed.
   */
  int TIME_LIMIT_SOFT_DEFAULT = 20 * 60 * 1000;
}
