/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.convenience.session;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.poseidas.ecardcore.model.ResultMajor;
import de.governikus.eumw.poseidas.ecardcore.model.ResultMinor;
import de.governikus.eumw.poseidas.eidserver.convenience.ChatOptionNotAllowedException;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoContainerImpl;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDCallback;
import de.governikus.eumw.poseidas.eidserver.ecardid.ECardIDServerI;
import de.governikus.eumw.poseidas.eidserver.ecardid.EIDInfoContainer;
import de.governikus.eumw.poseidas.eidserver.ecardid.SessionInput;


/**
 * Holds the sessions for ECardServlet. <br>
 * Warning: Current implementation will not work within a cluster! For clustered server, storage of session
 * must be changed (make sessions EJBs, keep links in JNDI or database?).
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
  private Map<String, Session> sessionMap = new HashMap<>();

  /**
   * Timeout to be set for started sessions
   */
  private Long timeout;

  /**
   * Listener used by the poseidas server
   */
  private ECardIDCallback listener;

  /**
   * Private instance creation
   */
  private SessionManager()
  {
  }

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


  private synchronized void startSession(SessionInput input)
  {
    // To start a session create one
    Session session = null;
    try
    {
      // If a timeout was set for this manager it will be used for the intern session timeout
      if (timeout == null)
      {
        // Session created with default timeout
        session = new Session(input);
      }
      else
      {
        // Session created with specific timeout
        session = new Session(input, timeout);
      }
      // Session is registered to the server

      sessionPut(input, session);
    }
    catch (ChatOptionNotAllowedException e)
    {
      EIDInfoContainerImpl container = new EIDInfoContainerImpl();
      container.setResult(ResultMajor.ERROR, ResultMinor.SAL_SECURITY_CONDITION_NOT_SATISFIED, e.getMessage());
      listener.seteIDSessionComplete(input.getSessionID(), container);
    }
  }

  /**
   * Get the session object for session identifier
   *
   * @param sessionId identifier from session
   * @return the searched session
   */
  public Session getSession(String sessionId)
  {
    if (sessionMap == null || sessionId == null)
    {
      return null;
    }
    Session result = sessionMap.get(sessionId);
    if (result == null)
    {
      SessionInput sessionInput = listener.getSessionInput(sessionId);
      if (sessionInput == null)
      {
        return null;
      }
      startSession(sessionInput);
      result = sessionMap.get(sessionId);
    }
    return result;
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
   * Returns the session timeout if set otherwise null is returned
   *
   * @return the session timeout for this manager
   */
  public Long getSessionTimeout()
  {
    return this.timeout;
  }

  /**
   * Indicates how many sessions are in use
   *
   * @return number of active sessions
   */
  public int getSessionsCount()
  {
    if (sessionMap == null)
    {
      return 0;
    }
    else
    {
      return sessionMap.size();
    }
  }

  /**
   * Stops a session
   *
   * @param sessionId
   * @param eidInfoContainer
   */
  public synchronized Session stopSession(String sessionId, EIDInfoContainer eidInfoContainer)
  {
    Session removedSession = sessionMap.get(sessionId);
    if (removedSession != null)
    {
      listener.seteIDSessionComplete(removedSession.getSessionInput().getSessionID(), eidInfoContainer);
      sessionMap.remove(sessionId);
      LOG.debug(removedSession.getSessionInput().getLogPrefix() + "Session: " + removedSession + " stopped");
      return removedSession;
    }
    else
    {
      LOG.debug("Session not stopped: Session '" + sessionId + "'to be stopped is not an active session");
    }

    return null;
  }

  /**
   * Sets the timeout for sessions provided by this manager
   *
   * @param timeout to be set
   */
  public void setSessionTimeouts(Long timeout)
  {
    this.timeout = timeout;
  }


  /**
   * Session handling for the session manager
   *
   * @param input for session to be created
   * @param session to be set
   */
  private void sessionPut(SessionInput input, Session session)
  {
    // Indicates if session map was used already or must be initiated
    if (sessionMap == null)
    {
      sessionMap = new HashMap<>();
    }
    // Put the session to the manager
    sessionMap.put(input.getSessionID(), session);
    // Optimize map only with more than one session
    if (sessionMap.size() > 1)
    {
      // Get the eCard Comparator to be able to compare sessions by there timeout
      SessionComparator comparator = new SessionComparator(sessionMap, System.currentTimeMillis());
      // Create a sorted map for all sessions
      TreeMap<String, Session> sort = new TreeMap<>(comparator);
      // Put all sessions to be sorted
      sort.putAll(sessionMap);
      // Get the latest invalid session. This is the point where the map could be cut
      String sessionId = comparator.getLatestInvalidSessionId();
      // Invalid session as anchor
      if (sessionId != null)
      {
        // Cut map and receive only valid sessions in the server list
        sessionMap = new HashMap<>(sort.subMap(sessionId, false, sort.lastKey(), true));
      }
      else
      {
        // All session are valid so put them back to server list
        // NOTE: do not use a TreeMap, otherwise the comparator will be used again and throw overflow
        sessionMap = new HashMap<>(sort);
      }
    }
  }

  @Override
  public void setECardIDCallbackListener(ECardIDCallback listener)
  {
    this.listener = listener;
  }
}
