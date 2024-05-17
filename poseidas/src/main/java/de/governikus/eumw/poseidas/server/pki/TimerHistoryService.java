package de.governikus.eumw.poseidas.server.pki;

import java.util.Date;
import java.util.List;

import org.springframework.stereotype.Service;

import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;
import de.governikus.eumw.poseidas.server.pki.repositories.TimerHistoryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Service to get or save {@link TimerHistory} entities.
 *
 * @author tca
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TimerHistoryService
{

  private final TimerHistoryRepository timerHistoryRepository;

  /**
   * Creates and saves a new {@link TimerHistory} Entity. Also deletes the oldest entity of the timerType if already 50
   * entities saved in the database.
   *
   * @param timerType The type of the timer
   *          ({@link de.governikus.eumw.poseidas.server.pki.entities.TimerHistory.TimerType}).
   * @param message The message for the timer (success or failure message).
   * @param success Boolean which shows the execution result of the timer.
   * @param timerExecution Boolean which specifies if the method is called by a timer execution. If false no data will
   *          be stored.
   */
  public void saveTimer(TimerHistory.TimerType timerType, String message, boolean success, boolean timerExecution)
  {
    if (timerExecution)
    {
      TimerHistory th = new TimerHistory(timerType, message, new Date(), success);
      List<TimerHistory> allTimerSortByDate = timerHistoryRepository.findAllByTimerTypeOrderByTimestampAsc(timerType);
      if (50 == allTimerSortByDate.size())
      {
        TimerHistory oldestTimer = allTimerSortByDate.get(0);
        timerHistoryRepository.delete(oldestTimer);
      }
      timerHistoryRepository.save(th);
      log.debug("Timer execution for %s saved in database.".formatted(timerType));
    }
  }

  /**
   * Reads all {@link TimerHistory} entities from the database by the timerType.
   * 
   * @param timerType The type of the timer
   *          ({@link de.governikus.eumw.poseidas.server.pki.entities.TimerHistory.TimerType}).
   * @return List of all stored {@link TimerHistory} entities for the timerType.
   */
  public List<TimerHistory> getAllTimers(TimerHistory.TimerType timerType)
  {
    return timerHistoryRepository.findAllByTimerTypeOrderByTimestampAsc(timerType);
  }

}
