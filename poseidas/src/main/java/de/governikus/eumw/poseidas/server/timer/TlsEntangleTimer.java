package de.governikus.eumw.poseidas.server.timer;

import static de.governikus.eumw.poseidas.server.timer.TimerValues.SECOND;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.springframework.scheduling.Trigger;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.EntanglementTimerType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.CvcEntanglementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Timer for entangling the server certificate with the CVCs of service providers.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class TlsEntangleTimer implements Runnable
{

  private final ConfigurationService configurationService;

  private final CvcEntanglementService entanglementService;

  /**
   * Execute the entanglement
   */
  @Override
  public void run()
  {
    TimerConfigurationType timerConfiguration = configurationService.getConfiguration()
                                                                    .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                    .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                                    .orElse(null);

    if (!Optional.ofNullable(timerConfiguration)
                 .map(TimerConfigurationType::getTlsEntangleRenewal)
                 .map(EntanglementTimerType::isAutomaticTlsEntangleActive)
                 .orElse(true))
    {
      log.debug("Automatic TLS server certificate entanglement is disabled.");
      return;
    }
    if (Optional.ofNullable(timerConfiguration).map(TimerConfigurationType::getTlsEntangleRenewal).isEmpty())
    {
      log.debug("No timer configuration present. Default is to run automatic entanglement anyway.");
    }
    entanglementService.checkEntanglement()
                       .forEach((s,
                                 m) -> log.debug("Execution of TLS server certificate entangle timer for sp: {} finished with code: {} and message: {}",
                                                 s.getName(),
                                                 m.getCode().getCode(),
                                                 m.getDetails()));
  }

  Trigger getTlsEntangleTrigger(List<Instant> nextExecutions)
  {
    return triggerContext -> {
      log.debug("Handle TLS server certificate entangle timer");
      Date lastExecution = triggerContext.lastScheduledExecutionTime();
      Date lastCompletion = triggerContext.lastCompletionTime();
      if (lastExecution == null || lastCompletion == null)
      {
        long initialDelay = 30 * SECOND;
        Date date = new Date(triggerContext.getClock().millis() + initialDelay);
        log.debug("First TLS server certificate entangle timer task will be executed immediately");
        log.debug("TLS server certificate entangle timer task will be executed at {}", date);
        nextExecutions.add(date.toInstant());
        return date.toInstant();
      }
      Instant nextExecutiontime = lastCompletion.toInstant().plusMillis(getTlsEntangleTimer());
      nextExecutions.add(nextExecutiontime);
      Date date = Date.from(nextExecutiontime);
      log.debug("TLS server certificate entangle timer task will be executed at {}", date);
      return date.toInstant();
    };
  }

  private long getTlsEntangleTimer()
  {
    TimerConfigurationType timerConfiguration = configurationService.getConfiguration()
                                                                    .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                    .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                                    .orElse(null);

    if (timerConfiguration != null && timerConfiguration.getTlsEntangleRenewal() != null)
    {
      EntanglementTimerType tlsEntangleRenewal = timerConfiguration.getTlsEntangleRenewal();
      if (StringUtils.isNotBlank(tlsEntangleRenewal.getUnit().value()) && tlsEntangleRenewal.getLength() != 0)
      {
        TimerUnit unit = tlsEntangleRenewal.getUnit();
        Integer length = tlsEntangleRenewal.getLength();
        if (log.isDebugEnabled())
        {
          log.debug("Set timer value for TLS server certificate entangle renewal to every {} {}", length, unit.value());
        }
        return ApplicationTimer.getUnitOfTime(tlsEntangleRenewal.getUnit()) * tlsEntangleRenewal.getLength();
      }
    }
    TimerUnit hour = TimerUnit.HOURS;
    int length = 1;
    if (log.isDebugEnabled())
    {
      log.debug("No timer configuration for TLS server certificate entangle timer present. Set timer to default value every {} {}",
                length,
                hour.value());
    }
    return ApplicationTimer.getUnitOfTime(hour) * length;
  }
}
