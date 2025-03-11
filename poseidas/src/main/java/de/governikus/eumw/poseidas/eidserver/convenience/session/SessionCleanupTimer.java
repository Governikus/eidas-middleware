package de.governikus.eumw.poseidas.eidserver.convenience.session;

import java.util.concurrent.TimeUnit;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;


/**
 * A timer to remove invalid sessions.
 */
@Component
@Slf4j
public class SessionCleanupTimer
{

  SessionManager sessionManager = SessionManager.getInstance();

  /**
   * This method is a timer with a delay - configured by the property <i>poseidas.session.cleanup-timer-seconds</i>. The
   * default is 15 (seconds). The timer checks the session managers session storage for invalid sessions.
   */
  @Scheduled(fixedDelayString = "${poseidas.session.cleanup-timer-seconds:15}", timeUnit = TimeUnit.SECONDS)
  public void cleanupSessions()
  {
    log.debug("Checking session manager for invalid sessions");
    sessionManager.removeInvalidSessions();
    log.trace("Finished checking session manager for invalid sessions");
  }
}
