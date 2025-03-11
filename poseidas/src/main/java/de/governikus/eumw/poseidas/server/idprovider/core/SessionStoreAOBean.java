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

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.TypedQuery;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.eidascommon.ErrorCode;
import de.governikus.eumw.eidascommon.ErrorCodeException;



/**
 * Access to sessions stored in the database
 */
@Repository
public class SessionStoreAOBean implements SessionStoreAO
{

  private static final Log LOG = LogFactory.getLog(SessionStoreAOBean.class);


  private int numberSessionsSinceLastCleanUp = 0;

  /**
   * Number of sessions which may be in process before searching for outdated sessions.
   */
  int maxPendingRequests = MAX_PENDING_DEFAULT;

  /**
   * existing sessions are not counted each time but only after storing so many sessions from this JVM.
   */
  int cleanUpDatabaseAfterRequests = maxPendingRequests / 4;

  /**
   * If there are too many requests, requests older that 3 minutes may be deleted to avoid database overflow.
   */
  int timeLimitHard = TIME_LIMIT_HARD_DEFAULT;

  /**
   * When we run the general cleanup all sessions older then 20 minutes will be removed.
   */
  int timeLimitSoft = TIME_LIMIT_SOFT_DEFAULT;

  @PersistenceContext(/*unitName = "eID-Server"*/)
  EntityManager entityManager;

  @Override
  public <T extends StoreableSession> T getSession(String sessionId, Class<T> type)
  {
    SessionInStore store = null;
    if (sessionId != null)
    {
      store = entityManager.find(SessionInStore.class, new SessionInStorePK(sessionId, type.getSimpleName()));
    }
    if (store == null || store.getSession() == null)
    {
      return null;
    }
    return type.cast(store.getSession());
  }

  @Override
  public <T extends StoreableSession> T getSessionByRequestId(String requestId, Class<T> type)
  {
    try
    {
      TypedQuery<SessionInStore> query = entityManager.createNamedQuery("getByRequestId",
                                                                        SessionInStore.class);
      query.setParameter("className", type.getSimpleName());
      query.setParameter("requestId", requestId);
      SessionInStore store = query.getSingleResult();

      if (store == null || store.getSession() == null)
      {
        return null;
      }
      return type.cast(store.getSession());
    }
    catch (NoResultException e)
    {
      if (LOG.isDebugEnabled())
      {
        LOG.debug("No session found for requestId: " + requestId, e);
      }
      return null;
    }
  }

  @Override
  public void storeSession(StoreableSession session) throws ErrorCodeException
  {
    String sessionId = session.getSessionId();
    SessionInStore store = null;
    SessionInStorePK pk = new SessionInStorePK(sessionId, session.getClass().getSimpleName());
    if (sessionId != null)
    {
      store = entityManager.find(SessionInStore.class, pk);
    }
    if (store == null)
    {
      numberSessionsSinceLastCleanUp++;
      if (numberSessionsSinceLastCleanUp > cleanUpDatabaseAfterRequests)
      {
        try
        {
          cleanup();
        }
        catch (ErrorCodeException e)
        {
          removeRequestId(session);
          throw e;
        }
      }
      store = new SessionInStore(pk, session, session.getCreationTime(), session.getRequestId());
      entityManager.persist(store);
      return;
    }
    if (store.getSession().getClass() != session.getClass())
    {
      throw new IllegalArgumentException("Can not overwrite a session in storage with a session of different type.");
    }
    store.setSession(session);
    entityManager.merge(store);
  }

  @Override
  public void removeSession(StoreableSession session)
  {
    if (session != null)
    {
      String sessionId = session.getSessionId();
      SessionInStore store = entityManager.find(SessionInStore.class,
                                                new SessionInStorePK(sessionId,
                                                                     session.getClass().getSimpleName()));
      if (store != null)
      {
        entityManager.remove(store);
      }
      removeRequestId(session);
    }
  }

  private void removeRequestId(StoreableSession session)
  {
    String requestId = session.getRequestId();
    if (requestId == null)
    {
      return;
    }
    RequestIdStore requestIdStore = entityManager.find(RequestIdStore.class, requestId);
    if (requestIdStore != null)
    {
      entityManager.remove(requestIdStore);
    }
    else
    {
      LOG.warn("The requestId to delete does exist: requestId: \"" + requestId + "\" sessionId: \""
               + session.getSessionId() + "\"");
    }
  }

  @Override
  public void addRequestId(String requestId) throws ErrorCodeException
  {
    if (entityManager.find(RequestIdStore.class, requestId) != null)
    {
      throw new ErrorCodeException(ErrorCode.DUPLICATE_REQUEST_ID, requestId);
    }
    RequestIdStore store = new RequestIdStore(requestId);
    entityManager.persist(store);
  }

  @Override
  public long getNumberSessions()
  {
    TypedQuery<Long> query = entityManager.createNamedQuery("getNumberEntries", Long.class);
    return query.getSingleResult();
  }

  private synchronized void cleanup() throws ErrorCodeException
  {
    long numberEntries = getNumberSessions();
    if (numberEntries > maxPendingRequests)
    {
      deteleOldSessions(timeLimitSoft);
      numberEntries = getNumberSessions();
    }
    if (numberEntries > maxPendingRequests)
    {
      LOG.error("There is an overflow, deleting all not ended sessions older than " + (timeLimitSoft / 1000)
                + " seconds did not helped, will delete all sessions older than " + (timeLimitHard / 1000)
                + " seconds");
      deteleOldSessions(timeLimitHard);
      numberEntries = getNumberSessions();
    }
    if (numberEntries > maxPendingRequests)
    {
      throw new ErrorCodeException(ErrorCode.TOO_MANY_OPEN_SESSIONS, Long.toString(numberEntries),
                                   Integer.toBinaryString(maxPendingRequests));
    }
    numberSessionsSinceLastCleanUp = 0;
  }

  private void deteleOldSessions(int timeLimit)
  {
    long killTime = System.currentTimeMillis() - timeLimit;

    TypedQuery<SessionInStore> query = entityManager.createNamedQuery("getOldEntries", SessionInStore.class);
    query.setParameter("creationTime", Long.valueOf(killTime));
    for ( SessionInStore entry : query.getResultList() )
    {
      entityManager.remove(entry);
      entry.getSession().removed(true);
      removeRequestId(entry.getSession());
    }
  }

  @Override
  public <T extends StoreableSession> Collection<T> getAllSessions(Class<T> type)
  {
    TypedQuery<SessionInStore> query = entityManager.createNamedQuery("getAllForClass", SessionInStore.class);
    query.setParameter("className", type.getSimpleName());
    Collection<T> result = new HashSet<>();
    for ( SessionInStore entry : query.getResultList() )
    {
      result.add(type.cast(entry.getSession()));
    }
    return result;
  }

  @Override
  public void setMaxPendingRequests(int maxPendingRequests)
  {
    this.maxPendingRequests = maxPendingRequests;
  }
}
