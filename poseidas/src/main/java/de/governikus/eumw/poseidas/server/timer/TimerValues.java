/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This class provides beans that return timer rates as strings that can be used
 * in @{@link org.springframework.scheduling.annotation.Scheduled} annotations. This way the rate does not have to be a
 * constant number in the @{@link ApplicationTimer} class itself and can be calculated more easily.
 */
@Configuration
@Slf4j
@AllArgsConstructor
public class TimerValues
{

  static final long SECOND = 1000;

  static final long MINUTE = SECOND * 60;

  static final long HOUR = MINUTE * 60;


  @Bean
  public String getFullBlacklistRate()
  {
    String timerName = "Full blacklist renewal";

    // Set default value for once a month
    String rate = String.valueOf(30 * 24 * HOUR);
    logRateForTimer(timerName, rate);
    return rate;
  }

  @Bean
  public String getKeyLockRate()
  {
    String timerName = "Check key locks";

    // Set default value to every minute
    String rate = String.valueOf(MINUTE);
    logRateForTimer(timerName, rate);
    return rate;
  }

  @Bean
  public String getCvcRscRenewDelay(@Value("${timer.invalidCvcRscRenew.delayInSeconds:120}") int rate)
  {
    String timerName = "Invalid cvc renewal with rsc timer";
    String rateAsString = String.valueOf(rate);
    logRateForTimer(timerName, String.valueOf(rate * 1000));
    return rateAsString;
  }

  @Bean
  public String getRSCRate()
  {
    String timerName = "RSC renewal check";

    // Set default value to every day
    String rate = String.valueOf(24 * HOUR);

    logRateForTimer(timerName, rate);
    return rate;
  }

  @Bean
  // The value can be removed when the execution of the timer is not configurable anymore.
  public String getTLSClientRate(@Value("${poseidas.tls.renewal.active:false}") boolean automaticTlsRenewal)
  {
    String timerName = "TLS client renewal check";

    // Set default value to every day
    String rate = String.valueOf(24 * HOUR);

    // Only log rate for timer when automatic tls renewal is enabled
    // This if-statement can be removed when the execution of the timer is not configurable anymore.
    if (automaticTlsRenewal)
    {
      logRateForTimer(timerName, rate);
    }
    return rate;
  }

  protected void logRateForTimer(String timerName, String rate)
  {
    log.info(" The timer '{}' will be executed every {}", timerName, getHumanReadableRate(rate));
  }

  String getHumanReadableRate(String rateInMs)
  {
    long rate = Long.parseLong(rateInMs);
    if (rate >= HOUR && rate % HOUR == 0)
    {
      return rate / HOUR + " hours";
    }
    else if (rate >= MINUTE && rate % MINUTE == 0)
    {
      return rate / MINUTE + " minutes";
    }
    else if (rate >= SECOND && rate % SECOND == 0)
    {
      return rate / SECOND + " seconds";
    }
    else
    {
      return rateInMs + " milliseconds";
    }
  }
}
