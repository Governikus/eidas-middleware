/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import java.time.Instant;
import java.util.Date;
import java.util.List;

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
 * This class manages the timer for the global list retrieval. The class implements the Runnable interface. The
 * {@link #run() run} method is used to retrieve the Master List and Defect List. The
 * {@link #getGlobalListTrigger(List) getGlobalListTrigger} method determines how often the timer runs.
 *
 * @see ApplicationTimer
 */

@Component
@RequiredArgsConstructor
@Slf4j
public class GlobalListTimer implements Runnable
{

  private final PermissionDataHandling permissionDataHandling;

  private final ConfigurationService configurationService;

  @Override
  public void run()
  {
    log.debug("Execute global list Timer");
    permissionDataHandling.renewMasterAndDefectList(true);
  }

  Trigger getGlobalListTrigger(List<Instant> nextExecutions)
  {
    return triggerContext -> {
      log.debug("Handle trigger for global list timer");
      Date lastExecution = triggerContext.lastScheduledExecutionTime();
      Date lastCompletion = triggerContext.lastCompletionTime();
      if (lastExecution == null || lastCompletion == null)
      {
        long initialDelay = getGlobalListTimer();
        Date date = new Date(triggerContext.getClock().millis() + initialDelay);
        log.debug("First global list timer task will executed with an initial delay of {} milliseconds", initialDelay);
        log.debug("Global list timer task will be executed at {}", date);
        nextExecutions.add(date.toInstant());
        return date.toInstant();
      }
      Instant nextExecutiontime = lastCompletion.toInstant().plusMillis(getGlobalListTimer());
      nextExecutions.add(nextExecutiontime);
      Date date = Date.from(nextExecutiontime);
      log.debug("Global list timer task will be executed at {}", date);
      return date.toInstant();
    };
  }

  private long getGlobalListTimer()
  {
    TimerConfigurationType timerConfiguration = configurationService.getConfiguration()
                                                                    .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                    .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                                    .orElse(null);
    if (timerConfiguration != null && timerConfiguration.getMasterAndDefectListRenewal() != null)
    {
      TimerType renewal = timerConfiguration.getMasterAndDefectListRenewal();
      if (renewal.getLength() != 0 && StringUtils.isNotBlank(renewal.getUnit().value()))
      {
        TimerUnit unit = renewal.getUnit();
        Integer length = renewal.getLength();
        if (log.isDebugEnabled())
        {
          log.debug("Set timer value for global list renewal to every {} {}", length, unit.value());
        }
        return ApplicationTimer.getUnitOfTime(renewal.getUnit()) * renewal.getLength();
      }
    }

    // Set default value to every 2 hours
    TimerUnit hour = TimerUnit.HOURS;
    int length = 2;
    if (log.isDebugEnabled())
    {
      log.debug("No timer configuration for global list timer present. Set timer to default value every {} {}",
                length,
                hour.value());
    }
    return ApplicationTimer.getUnitOfTime(hour) * length;
  }
}
