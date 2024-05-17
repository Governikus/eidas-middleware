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
import static de.governikus.eumw.poseidas.server.timer.TimerValues.SECOND;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory.TimerType;
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

  public static final long RSC_TIMER_START_DELAY_MILS = 2 * MINUTE;

  public static final long FULL_BL_TIMER_START_DELAY_MILS = 30 * SECOND;

  private final PermissionDataHandling permissionDataHandling;

  private final RequestSignerCertificateService rscService;

  private final CvcRenewalTimer cvcRenewalTimer;

  private final BlackListTimer blackListTimer;

  private final GlobalListTimer globalListTimer;

  private final CrlRenewalTimer crlRenewalTimer;

  private final TlsEntangleTimer tlsEntangleTimer;

  private final String getFullBlacklistRate;

  private final String getRSCRate;

  /**
   * Deactivates the automatic tls client cert renewal if false / not set. Can be removed when the execution of the
   * timer is not configurable anymore.
   */
  @Value("${poseidas.tls.renewal.active:false}")
  private boolean automaticTlsRenewal;

  /**
   * Store planned timer executions
   */
  Map<TimerType, List<Instant>> nextTimerExecutions = new EnumMap<>(TimerType.class);

  /**
   * Fill nextTimerExecutions map with empty lists on startup.
   */
  @PostConstruct
  void init()
  {
    Arrays.stream(TimerType.values()).forEach(v -> nextTimerExecutions.putIfAbsent(v, new ArrayList<>(2)));

    // Set first run for timer that are scheduled with @Scheduled
    nextTimerExecutions.get(TimerType.BLACK_LIST_TIMER).add(Instant.now().plusMillis(FULL_BL_TIMER_START_DELAY_MILS));
    nextTimerExecutions.get(TimerType.RSC_RENEWAL).add(Instant.now().plusMillis(RSC_TIMER_START_DELAY_MILS));
    // Only set next timer execution for tls client renewal when the property is set to "true".
    // This if-else-statement can be removed when the execution of the timer is not configurable anymore.
    if (automaticTlsRenewal)
    {
      nextTimerExecutions.get(TimerType.TLS_CLIENT_RENEWAL)
                         .add(Instant.now()
                                     .plusMillis(ApplicationTimerTlsClientCerts.TLS_CLIENT_TIMER_START_DELAY_MILS));
    }
    else
    {
      // We don't need this timer if automaticTlsRenewal is false / not set.
      nextTimerExecutions.remove(TimerType.TLS_CLIENT_RENEWAL);
    }
  }

  @Scheduled(fixedRate = 5, timeUnit = TimeUnit.MINUTES, initialDelay = 30 * TimerValues.SECOND)
  public void cleanOldTimerExecutions()
  {
    Predicate<Instant> olderThenFiveMinutes = d -> d.isBefore(Instant.now().minus(5, ChronoUnit.MINUTES));
    nextTimerExecutions.forEach((k, v) -> v.removeIf(olderThenFiveMinutes));
  }

  @Scheduled(fixedRateString = "#{@getFullBlacklistRate}", initialDelay = FULL_BL_TIMER_START_DELAY_MILS)
  public void renewFullBlackList()
  {
    permissionDataHandling.renewBlackList(false, true);
    var nextRun = Instant.now().plus(Long.parseLong(getFullBlacklistRate), ChronoUnit.MILLIS);
    nextTimerExecutions.get(TimerType.BLACK_LIST_TIMER).add(nextRun);
  }

  @Scheduled(fixedRateString = "#{@getRSCRate}", initialDelay = RSC_TIMER_START_DELAY_MILS)
  public void renewRequestSigners()
  {
    rscService.renewOutdated();
    var nextRun = Instant.now().plus(Long.parseLong(getRSCRate), ChronoUnit.MILLIS);
    nextTimerExecutions.get(TimerType.RSC_RENEWAL).add(nextRun);
  }

  @Override
  public void configureTasks(ScheduledTaskRegistrar taskRegistrar)
  {
    taskRegistrar.addTriggerTask(cvcRenewalTimer,
                                 cvcRenewalTimer.getCvcRenewalTrigger(nextTimerExecutions.get(TimerType.CVC_RENEWAL_TIMER)));
    taskRegistrar.addTriggerTask(blackListTimer,
                                 blackListTimer.getBlackListTrigger(nextTimerExecutions.get(TimerType.BLACK_LIST_TIMER)));
    taskRegistrar.addTriggerTask(globalListTimer,
                                 globalListTimer.getGlobalListTrigger(nextTimerExecutions.get(TimerType.GLOBAL_LIST_TIMER)));
    taskRegistrar.addTriggerTask(crlRenewalTimer,
                                 crlRenewalTimer.getCrlTrigger(nextTimerExecutions.get(TimerType.CRL_RENEWAL_TIMER)));
    taskRegistrar.addTriggerTask(tlsEntangleTimer,
                                 tlsEntangleTimer.getTlsEntangleTrigger(nextTimerExecutions.get(TimerType.TLS_ENTANGLE_TIMER)));
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

  public Optional<Instant> getNextTimerExecution(TimerType timer)
  {
    // This if-else-statement can be removed when the execution of the timer is not configurable anymore.
    if (!automaticTlsRenewal && TimerType.TLS_CLIENT_RENEWAL.equals(timer))
    {
      return Optional.empty();
    }
    // Get the next timer execution from ApplicationTimerTlsClientCerts for the ui.
    else if (TimerType.TLS_CLIENT_RENEWAL.equals(timer))
    {
      return ApplicationTimerTlsClientCerts.getNextTimerExecution();
    }
    return nextTimerExecutions.get(timer).stream().filter(d -> Instant.now().isBefore(d)).sorted().findFirst();
  }
}
