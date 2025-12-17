package de.governikus.eumw.poseidas.server.timer;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.springframework.scheduling.Trigger;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.HsmKeyDeletionType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.poseidas.server.pki.TimerHistoryService;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Component
@Slf4j
@RequiredArgsConstructor
public class HsmKeyDeletionTimer implements Runnable
{

  private static final TimerUnit DEFAULT_TIMER_UNIT = TimerUnit.HOURS;

  private static final int DEFAULT_TIMER_LENGTH = 24;

  private static final int INITIAL_DELAY_SECONDS = 42;

  private final ConfigurationService configurationService;

  private final HSMServiceHolder hsmServiceHolder;

  private final TimerHistoryService timerHistoryService;

  /**
   * Execute the entanglement
   */
  @Override
  public void run()
  {

    if (!configurationService.getConfiguration()
                             .map(EidasMiddlewareConfig::getEidConfiguration)
                             .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                             .map(TimerConfigurationType::getHsmKeyDeletion)
                             .map(HsmKeyDeletionType::isAutomaticHsmKeyDeletionActive)
                             .orElse(false))
    {
      log.debug("Automatic HSM key deletion is disabled");
      return;
    }

    try
    {
      var result = hsmServiceHolder.deleteOutdatedKeys();
      timerHistoryService.saveTimer(TimerHistory.TimerType.HSM_DELETION_TIMER,
                                    result.message(),
                                    result.success(),
                                    true);
    }
    catch (HSMException | IOException e)
    {
      log.warn("Could not delete outdated keys in HSM", e);
      timerHistoryService.saveTimer(TimerHistory.TimerType.HSM_DELETION_TIMER,
                                    "Exception while deleting outdated keys in HSM:  %s (Check the log for more information)".formatted(e.getMessage()),
                                    false,
                                    true);
    }
    log.debug("HSM key deletion timer finished");
  }

  Trigger getHsmDeletionTrigger(List<Instant> nextExecutions)
  {
    return triggerContext -> {
      log.debug("Handle HSM key deletion timer");
      Instant lastExecution = triggerContext.lastScheduledExecution();
      Instant lastCompletion = triggerContext.lastCompletion();

      if (lastExecution == null || lastCompletion == null)
      {
        Instant nextExecution = triggerContext.getClock().instant().plusSeconds(INITIAL_DELAY_SECONDS);
        log.debug("First HSM key deletion timer task will be executed immediately");
        log.debug("HSM key deletion timer task will be executed at {}", nextExecution);
        nextExecutions.add(nextExecution);
        return nextExecution;
      }

      Instant nextExecutiontime = lastCompletion.plusMillis(getMillsToNextExec());
      nextExecutions.add(nextExecutiontime);
      Date date = Date.from(nextExecutiontime);
      log.debug("HSM key deletion timer task will be executed at {}", date);
      return date.toInstant();
    };
  }

  private long getMillsToNextExec()
  {
    Optional<HsmKeyDeletionType> optionalHsmKeyDeletion = configurationService.getConfiguration()
                                                                              .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                              .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                                              .map(TimerConfigurationType::getHsmKeyDeletion);

    if (optionalHsmKeyDeletion.isEmpty() || optionalHsmKeyDeletion.map(HsmKeyDeletionType::getLength).isEmpty()
        || optionalHsmKeyDeletion.map(HsmKeyDeletionType::getUnit)
                                 .map(TimerUnit::value)
                                 .map(StringUtils::isBlank)
                                 .orElse(true))
    {
      log.debug("No timer configuration for HSM key deletion timer present. Set timer to default value every {} {}",
                DEFAULT_TIMER_LENGTH,
                DEFAULT_TIMER_UNIT.value());

      return getDefault();
    }

    var hsmKeyDeletionType = optionalHsmKeyDeletion.get();

    TimerUnit unit = hsmKeyDeletionType.getUnit();
    Integer length = hsmKeyDeletionType.getLength();

    log.debug("Set timer value for HSM key deletion timer to every {} {}", length, unit.value());

    return ApplicationTimer.getUnitOfTime(unit) * length;
  }

  private static long getDefault()
  {
    return ApplicationTimer.getUnitOfTime(DEFAULT_TIMER_UNIT) * DEFAULT_TIMER_LENGTH;
  }
}
