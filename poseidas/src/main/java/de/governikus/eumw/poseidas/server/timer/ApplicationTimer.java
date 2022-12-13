/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import static de.governikus.eumw.poseidas.server.timer.TimerValues.HOUR;
import static de.governikus.eumw.poseidas.server.timer.TimerValues.MINUTE;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This class handles the application timers. The timers for CVC renewal, delta Black List, global lists and CRL renewal
 * can be configured dynamically in the eumw configuration. The timers for renew full Black List and renew RSC are
 * static.
 */

@Component
@Slf4j
@RequiredArgsConstructor
public class ApplicationTimer implements SchedulingConfigurer
{

  private final PermissionDataHandling permissionDataHandling;

  private final RequestSignerCertificateService rscService;

  private final CvcRenewalTimer cvcRenewalTimer;

  private final BlackListTimer blackListTimer;

  private final GlobalListTimer globalListTimer;

  private final CrlRenewalTimer crlRenewalTimer;

  @Scheduled(fixedRateString = "#{@getFullBlacklistRate}", initialDelay = 30 * TimerValues.SECOND)
  public void renewFullBlackList()
  {
    permissionDataHandling.renewBlackList(false);
  }

  @Scheduled(fixedRateString = "#{@getRSCRate}", initialDelay = 2 * MINUTE)
  public void renewRequestSigners()
  {
    rscService.renewOutdated();
  }

  @Override
  public void configureTasks(ScheduledTaskRegistrar taskRegistrar)
  {
    taskRegistrar.addTriggerTask(cvcRenewalTimer, cvcRenewalTimer.getCvcRenewalTrigger());
    taskRegistrar.addTriggerTask(blackListTimer, blackListTimer.getBlackListTrigger());
    taskRegistrar.addTriggerTask(globalListTimer, globalListTimer.getGlobalListTrigger());
    taskRegistrar.addTriggerTask(crlRenewalTimer, crlRenewalTimer.getCrlTrigger());
  }

  static long getUnitOfTime(TimerUnit unitFromXML)
  {
    if (unitFromXML == TimerUnit.MINUTES)
    {
      return MINUTE;
    }
    if (unitFromXML == TimerUnit.HOURS)
    {
      return HOUR;
    }
    throw new IllegalArgumentException("Unsupported unit of time: " + unitFromXML);
  }
}
