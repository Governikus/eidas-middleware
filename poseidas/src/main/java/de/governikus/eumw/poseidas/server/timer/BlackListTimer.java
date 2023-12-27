/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import static de.governikus.eumw.poseidas.server.timer.TimerValues.HOUR;

import java.time.Instant;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.springframework.scheduling.Trigger;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This class manages the timer for the delta Black List retrieval. The class implements the Runnable interface. The
 * {@link #run() run} method is used to retrieve the delta Black List. The {@link #getBlackListTrigger()
 * getBlackListTrigger} method determines how often the timer runs.
 *
 * @see ApplicationTimer
 */

@Component
@Slf4j
@RequiredArgsConstructor
public class BlackListTimer implements Runnable
{

  private final PermissionDataHandling permissionDataHandling;

  private final ConfigurationService configurationService;

  @Override
  public void run()
  {
    log.debug("Execute Black List timer");
    permissionDataHandling.renewBlackList(true);
  }

  Trigger getBlackListTrigger()
  {
    return triggerContext -> {
      log.debug("Handle trigger for delta Black List timer");
      Date lastExecution = triggerContext.lastScheduledExecutionTime();
      Date lastCompletion = triggerContext.lastCompletionTime();
      if (lastExecution == null || lastCompletion == null)
      {
        long initialDelay = 2 * HOUR;
        Date date = new Date(triggerContext.getClock().millis() + initialDelay);
        log.debug("First delta Black List timer task will be executed with an initial delay of {} milliseconds",
                  initialDelay);
        log.debug("Black List timer task will be executed at {}", date);
        return date.toInstant();
      }
      Instant nextExecutiontime = lastCompletion.toInstant().plusMillis(getDeltaBlackListTimer());
      Date date = Date.from(nextExecutiontime);
      log.debug("Black List timer task will be executed at {}", date);
      return date.toInstant();
    };
  }

  private long getDeltaBlackListTimer()
  {
    TimerConfigurationType timerConfiguration = configurationService.getConfiguration()
                                                                    .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                    .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                                    .orElse(null);

    if (timerConfiguration != null && timerConfiguration.getBlacklistRenewal() != null)
    {
      TimerType blacklistRenewal = timerConfiguration.getBlacklistRenewal();
      if (StringUtils.isNotBlank(blacklistRenewal.getUnit().value()) && blacklistRenewal.getLength() != 0)
      {
        TimerUnit unit = blacklistRenewal.getUnit();
        Integer length = blacklistRenewal.getLength();
        if (log.isDebugEnabled())
        {
          log.debug("Set timer value for delta Black List renewal to every {} {}", length, unit.value());
        }
        return ApplicationTimer.getUnitOfTime(blacklistRenewal.getUnit()) * blacklistRenewal.getLength();
      }
    }
    TimerUnit hour = TimerUnit.HOURS;
    int length = 2;
    if (log.isDebugEnabled())
    {
      log.debug("No timer configuration for delta Black List timer present. Set timer to default value every {} {}",
                length,
                hour.value());
    }
    return ApplicationTimer.getUnitOfTime(hour) * length;
  }
}
