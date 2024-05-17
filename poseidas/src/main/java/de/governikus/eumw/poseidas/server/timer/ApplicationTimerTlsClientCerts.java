/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import static de.governikus.eumw.poseidas.server.timer.TimerValues.SECOND;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import jakarta.annotation.PostConstruct;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import de.governikus.eumw.poseidas.server.pki.TlsClientRenewalService;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory.TimerType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Separate class for renewal of Tls client certificate timer which is only called, if poseidas.tls.renewal.active is
 * "true" in the application.properties. This class can be removed when the execution of the timer is not configurable
 * anymore.
 */
@Configuration
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(name = "poseidas.tls.renewal.active", havingValue = "true")
public class ApplicationTimerTlsClientCerts implements SchedulingConfigurer
{

  public static final long TLS_CLIENT_TIMER_START_DELAY_MILS = 90 * SECOND;

  private final TlsClientRenewalService tlsClientService;

  private final String getTLSClientRate;

  /**
   * Store planned timer executions.
   */
  private static final Map<TimerType, List<Instant>> NEXT_TIMER_EXECUTIONS = new EnumMap<>(TimerType.class);

  /**
   * Fill nextTimerExecutions map with empty lists on startup.
   */
  @PostConstruct
  void init()
  {
    // We just need tls client renewal here
    NEXT_TIMER_EXECUTIONS.put(TimerType.TLS_CLIENT_RENEWAL, new ArrayList<>(2));

    NEXT_TIMER_EXECUTIONS.get(TimerType.TLS_CLIENT_RENEWAL)
                         .add(Instant.now()
                                     .plusMillis(ApplicationTimerTlsClientCerts.TLS_CLIENT_TIMER_START_DELAY_MILS));

  }

  @Scheduled(fixedRate = 5, timeUnit = TimeUnit.MINUTES, initialDelay = 30 * SECOND)
  public void cleanOldTimerExecutions()
  {
    Predicate<Instant> olderThenFiveMinutes = d -> d.isBefore(Instant.now().minus(5, ChronoUnit.MINUTES));
    NEXT_TIMER_EXECUTIONS.forEach((k, v) -> v.removeIf(olderThenFiveMinutes));
  }

  @Scheduled(fixedRateString = "#{@getTLSClientRate}", initialDelay = TLS_CLIENT_TIMER_START_DELAY_MILS)
  public void renewTlsClientCerts()
  {
    tlsClientService.renewOutdated();
    var nextRun = Instant.now().plus(Long.parseLong(getTLSClientRate), ChronoUnit.MILLIS);
    NEXT_TIMER_EXECUTIONS.get(TimerType.TLS_CLIENT_RENEWAL).add(nextRun);
  }

  /**
   * Get the next timer execution for the tls client renewal timer.
   *
   * @return The {@link Instant} for the timer
   */
  public static Optional<Instant> getNextTimerExecution()
  {
    return NEXT_TIMER_EXECUTIONS.get(TimerType.TLS_CLIENT_RENEWAL)
                                .stream()
                                .filter(d -> Instant.now().isBefore(d))
                                .sorted()
                                .findFirst();
  }

  @Override
  public void configureTasks(ScheduledTaskRegistrar taskRegistrar)
  {
    // Nothing to do here
  }
}
