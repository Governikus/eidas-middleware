/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import static de.governikus.eumw.poseidas.server.timer.TimerValues.SECOND;

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
 * This class manages the timer for the CVC renewal. The class implements the Runnable interface. The {@link #run() run}
 * method is used to renew CVCs. The {@link #getCvcRenewalTrigger() getCvcRenewalTrigger} method determines how often
 * the timer runs.
 *
 * @see ApplicationTimer
 */

@Component
@Slf4j
@RequiredArgsConstructor
public class CvcRenewalTimer implements Runnable
{

  private final PermissionDataHandling permissionDataHandling;

  private final ConfigurationService configurationService;

  @Override
  public void run()
  {
    log.debug("Execute CVC renewal");
    permissionDataHandling.renewOutdatedCVCs();
  }

  Trigger getCvcRenewalTrigger()
  {
    return triggerContext -> {
      log.debug("Handle trigger for CVC renewal timer");
      Date lastExecution = triggerContext.lastScheduledExecutionTime();
      Date lastCompletion = triggerContext.lastCompletionTime();
      if (lastExecution == null || lastCompletion == null)
      {
        long initialDelay = 5 * SECOND;
        Date date = new Date(triggerContext.getClock().millis() + initialDelay);
        log.debug("First CVC renewal timer task will executed with an initial delay of {} milliseconds", initialDelay);
        log.debug("CVC renewal timer task will be executed at {}", date);
        return date;
      }
      Instant nextExecutiontime = lastCompletion.toInstant().plusMillis(getCvcRenewalTimer());
      Date date = Date.from(nextExecutiontime);
      log.debug("CVC renewal timer task will be executed at {}", date);
      return date;
    };
  }

  private long getCvcRenewalTimer()
  {
    TimerConfigurationType timerConfiguration = configurationService.getConfiguration()
                                                                    .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                    .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                                    .orElse(null);
    if (timerConfiguration != null && timerConfiguration.getCertRenewal() != null)
    {
      TimerType certRenewal = timerConfiguration.getCertRenewal();
      if (certRenewal.getLength() != 0 && StringUtils.isNotBlank(certRenewal.getUnit().value()))
      {
        TimerUnit unit = certRenewal.getUnit();
        Integer length = certRenewal.getLength();
        if (log.isDebugEnabled())
        {
          log.debug("Set timer value for CVC renewal to every {} {}", length, unit.value());
        }
        return ApplicationTimer.getUnitOfTime(unit) * length;
      }
    }

    // Set default value to every hour
    TimerUnit hour = TimerUnit.HOURS;
    int length = 1;
    if (log.isDebugEnabled())
    {
      log.debug("No timer configuration for CVC renewal present. Set timer to default value every {} {}",
                length,
                hour.value());
    }
    return ApplicationTimer.getUnitOfTime(hour) * length;
  }
}
