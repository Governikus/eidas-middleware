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

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;



/**
 * Session storage implementation which keeps sessions in memory. Works only on one-JVM-systems but is much
 * faster than DB based implementation.
 *
 * @author tautenhahn
 */
public class SessionStoreAOBeanMemory implements SessionStoreAO
{

  private static final Log LOG = LogFactory.getLog(SessionStoreAOBeanMemory.class);

  /**
   * Number of requests which may be in process before searching for outdated requests.
   */
  private int maxPendingRequests = MAX_PENDING_DEFAULT;

  private final Map<String, StoreableSession> contentBySessionId = new ConcurrentHashMap<>();

  private final Map<String, StoreableSession> contentByRequestId = new ConcurrentHashMap<>();

  private final Set<String> requestIDs = ConcurrentHashMap.newKeySet();

  private String createKey(String sessionId, Class<? extends StoreableSession> type)
  {
    return sessionId + type.getSimpleName();
  }

  @Override
  public <T extends StoreableSession> T getSession(String sessionId, Class<T> type)
  {
    StoreableSession result = contentBySessionId.get(createKey(sessionId, type));
    if (result == null)
    {
      return null;
    }
    return type.cast(result);
  }

  @Override
  public <T extends StoreableSession> T getSessionByRequestId(String requestId, Class<T> type)
  {
    StoreableSession result = contentByRequestId.get(createKey(requestId, type));
    if (result == null)
    {
      return null;
    }
    return type.cast(result);
  }

  @Override
  public void storeSession(StoreableSession session) throws ErrorCodeException
  {
    String primKey = createKey(session.getSessionId(), session.getClass());
    if (!contentBySessionId.containsKey(primKey))
    {
      try
      {
        cleanup();
      }
      catch (ErrorCodeException e)
      {
        String requestId = session.getRequestId();
        if (requestId != null)
        {
          requestIDs.remove(requestId);
        }
        throw e;
      }
    }
    contentBySessionId.put(primKey, session);
    String requestID = session.getRequestId();
    if (requestID != null)
    {
      contentByRequestId.put(createKey(requestID, session.getClass()), session);
    }
  }

  @Override
  public void removeSession(StoreableSession session)
  {
    removeSession(session, false);
  }

  private void removeSession(StoreableSession session, boolean cleanup)
  {
    if (session != null)
    {
      String requestId = session.getRequestId();
      contentBySessionId.remove(createKey(session.getSessionId(), session.getClass()));
      if (requestId != null)
      {
        contentByRequestId.remove(createKey(requestId, session.getClass()));
      }
      if (cleanup)
      {
        session.removed(true);
      }
      if (requestId != null)
      {
        requestIDs.remove(requestId);
      }
    }
  }

  @Override
  public void addRequestId(String requestID) throws ErrorCodeException
  {
    if (!requestIDs.add(requestID))
    {
      throw new ErrorCodeException(ErrorCode.DUPLICATE_REQUEST_ID, requestID);
    }
  }

  private void cleanup() throws ErrorCodeException
  {
    if (contentBySessionId.size() > maxPendingRequests)
    {
      deteleOldSessions(TIME_LIMIT_SOFT_DEFAULT);
    }
    if (contentBySessionId.size() > maxPendingRequests)
    {
      if (LOG.isErrorEnabled())
      {
        LOG.error("There is an overflow, deleting all not ended sessions older than "
                  + (TIME_LIMIT_SOFT_DEFAULT / 1000) + "did not helped, will delete all sessions older than "
                  + (TIME_LIMIT_HARD_DEFAULT / 1000));
      }
      deteleOldSessions(TIME_LIMIT_HARD_DEFAULT);
    }
    if (contentBySessionId.size() > maxPendingRequests)
    {
      throw new ErrorCodeException(ErrorCode.TOO_MANY_OPEN_SESSIONS,
                                   Integer.toString(contentBySessionId.size()),
                                   Integer.toString(maxPendingRequests));
    }
  }

  private synchronized void deteleOldSessions(int timeLimit)
  {
    long killTime = System.currentTimeMillis() - timeLimit;
    for ( StoreableSession entry : contentBySessionId.values() )
    {
      if (entry.getCreationTime() < killTime)
      {
        removeSession(entry, true);
      }
    }
  }

  @Override
  public <T extends StoreableSession> Collection<T> getAllSessions(Class<T> type)
  {
    HashSet<T> result = new HashSet<>();
    for ( StoreableSession values : contentBySessionId.values() )
    {
      if (type.isInstance(values))
      {
        result.add(type.cast(values));
      }
    }
    return result;
  }

  @Override
  public void setMaxPendingRequests(int maxPendingRequests)
  {
    this.maxPendingRequests = maxPendingRequests;
  }

  @Override
  public long getNumberSessions()
  {
    return contentBySessionId.size();
  }
}
