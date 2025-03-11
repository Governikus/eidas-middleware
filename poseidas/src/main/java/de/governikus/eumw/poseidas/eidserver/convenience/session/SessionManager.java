/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience.session;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.eidserver.convenience.ChatOptionNotAllowedException;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoContainerImpl;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDCallback;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerI;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;
import de.governikus.eumw.poseidas.paosservlet.paos.handler.PaosHandlerException;


/**
 * Holds the sessions for ECardServlet. <br>
 * Warning: Current implementation will not work within a cluster! For clustered server, storage of session must be
 * changed (make sessions EJBs, keep links in JNDI or database?).
 *
 * @author Alexander Funk
 * @author <a href="mail:hme@bos-bremen.de">Hauke Mehrtens</a>
 */
public class SessionManager implements ECardIDServerI
{

  private static final Log LOG = LogFactory.getLog(SessionManager.class.getName());

  /**
   * Session container for all reported sessions
   */
  private final Map<String, Session> sessionMap = new ConcurrentHashMap<>();

  private final Set<Session> sessionLock = new HashSet<>();


  /**
   * Listener used by the poseidas server
   */
  private ECardIDCallback listener;

  /**
   * Private instance creation
   */
  private SessionManager()
  {}

  @SuppressWarnings("synthetic-access")
  private static final class InstanceHolder
  {

    static final SessionManager INSTANCE = new SessionManager();
  }

  /**
   * Return one and only instance of this class
   */

  public static SessionManager getInstance()
  {
    return InstanceHolder.INSTANCE;
  }

  private boolean requestSessionLock(Session session)
  {
    // Lock is currently on the whole session lock map. Putting the lock to the session object could improve performance
    synchronized (sessionLock)
    {
      return sessionLock.add(session);
    }
  }

  public void unlockSession(Session session)
  {
    synchronized (sessionLock)
    {
      sessionLock.remove(session);
      LOG.trace("Unlocked session: " + session);
    }
  }

  private void startSession(SessionInput input)
  {
    // To start a session create one
    Session session = null;
    try
    {

      // Session created with default timeout
      session = new Session(input);

      // Session is registered to the server

      sessionPut(input, session);
    }
    catch (ChatOptionNotAllowedException e)
    {
      if (LOG.isDebugEnabled())
      {
        LOG.debug("Failed to create session", e);
      }
      EIDInfoContainerImpl container = new EIDInfoContainerImpl();
      container.setResult(ResultMajor.ERROR, ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED, e.getMessage());
      listener.seteIDSessionComplete(input.getSessionID(), container);
    }
    synchronized (sessionLock)
    {
      sessionLock.remove(session);
    }


  }

  /**
   * Checks if a session id exists.
   *
   * @param sessionID
   * @return true or false
   */
  public boolean sessionIdExistsOrCanBeCreated(String sessionID)
  {
    return sessionMap.containsKey(sessionID) || listener.getSessionInput(sessionID) != null;
  }

  /**
   * Get the session object for session identifier
   *
   * @param sessionId identifier from session
   * @return the searched session
   */
  public Session getSession(String sessionId) throws PaosHandlerException
  {

    if (sessionId == null)
    {
      return null;
    }

    Session session = sessionMap.get(sessionId);
    if (session == null)
    {
      SessionInput sessionInput = getSessionInput(sessionId);
      if (sessionInput == null)
      {
        return null;
      }
      startSession(sessionInput);
      session = sessionMap.get(sessionId);
    }

    if (requestSessionLock(session))
    {
      LOG.trace("Successfully locked session: " + sessionId);
    }
    else
    {
      throw new PaosHandlerException("Session locked: " + sessionId, HttpStatus.FORBIDDEN.value());
    }

    return session;
  }

  /**
   * Get the session input set for this session
   *
   * @param sessionId to be able to identify the session and its input
   * @return input from session
   */
  public SessionInput getSessionInput(String sessionId)
  {
    if (listener == null)
    {
      return null;
    }
    return listener.getSessionInput(sessionId);
  }

  /**
   * Stops a session
   *
   * @param sessionId
   * @param eidInfoContainer
   */
  public void stopSession(String sessionId, EIDInfoContainer eidInfoContainer)
  {
    Session removedSession = sessionMap.get(sessionId);
    if (removedSession == null)
    {
      LOG.debug("Session not stopped: Session '" + sessionId + "'to be stopped is not an active session");
      return;
    }

    listener.seteIDSessionComplete(removedSession.getSessionInput().getSessionID(), eidInfoContainer);

    sessionMap.remove(sessionId);
    synchronized (sessionLock)
    {
      if (sessionLock.remove(removedSession))
      {
        LOG.trace("Removed session lock: " + sessionId);
      }
    }

    LOG.debug(removedSession.getSessionInput().getLogPrefix() + "Session: " + removedSession + " stopped");
  }


  /**
   * Session handling for the session manager
   *
   * @param input for session to be created
   * @param session to be set
   */
  private void sessionPut(SessionInput input, Session session)
  {
    // Put the session to the manager
    sessionMap.put(input.getSessionID(), session);
  }

  void removeInvalidSessions()
  {
    long currentTimeMillis = System.currentTimeMillis();
    List<String> invalidSessionIds = sessionMap.entrySet()
                                               .parallelStream()
                                               // Check if session is invalid
                                               .filter(s -> currentTimeMillis > s.getValue().getValidTo())
                                               .map(Map.Entry::getKey)
                                               .toList();

    LOG.trace("Removing %s invalid sessions".formatted(invalidSessionIds.size()));

    // Remove invalid sessions
    invalidSessionIds.forEach(sessionId -> {
      Session sessionToRemove = sessionMap.get(sessionId);
      if (sessionToRemove != null)
      {
        sessionMap.remove(sessionId);
        synchronized (sessionLock)
        {
          sessionLock.remove(sessionToRemove);
        }
      }
    });
  }

  @Override
  public void setECardIDCallbackListener(ECardIDCallback listener)
  {
    this.listener = listener;
  }
}
