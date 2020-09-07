/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import java.util.Calendar;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.poseidas.config.schema.TimerType;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import lombok.extern.slf4j.Slf4j;


/**
 * This class provides beans that return timer rates as strings that can be used
 * in @{@link org.springframework.scheduling.annotation.Scheduled} annotations. This way the rate does not
 * have to be a constant number in the @{@link ApplicationTimer} class itself and can be calculated more
 * easily.
 */
@Configuration
@Slf4j
public class TimerValues
{

  static final long SECOND = 1000;

  static final long MINUTE = SECOND * 60;

  static final long HOUR = MINUTE * 60;

  /**
   * Use this wrapper for the static access to the configuration in order to simplify the mocking of the timer
   * configuration in tests
   *
   * @return The timer configuration from the POSeIDAS.xml
   */
  @Bean
  TimerConfigurationType getTimerConfiguration()
  {
    return PoseidasConfigurator.getInstance().getCurrentConfig().getTimerConfiguration();
  }

  private static long getUnitOfTime(int unitFromXML)
  {
    if (unitFromXML == Calendar.MINUTE)
    {
      return MINUTE;
    }
    if (unitFromXML == Calendar.HOUR_OF_DAY)
    {
      return HOUR;
    }
    throw new IllegalArgumentException("Unsupported unit of time: " + unitFromXML);
  }

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
  public String getDeltaBlacklistRate(TimerConfigurationType timerConfiguration)
  {
    String timerName = "Delta blacklist renewal";

    // Check for configuration value
    if (timerConfiguration != null && timerConfiguration.getBlacklistRenewal() != null)
    {
      TimerType blacklistRenewal = timerConfiguration.getBlacklistRenewal();
      if (blacklistRenewal.getUnit() != 0 && blacklistRenewal.getLength() != 0)
      {
        String rate = String.valueOf(getUnitOfTime(blacklistRenewal.getUnit())
                                     * blacklistRenewal.getLength());
        logRateForTimer(timerName, rate);
        return rate;
      }
    }

    // Set default value for every 2 hours
    String rate = String.valueOf(2 * HOUR);
    logRateForTimer(timerName, rate);
    return rate;
  }

  @Bean
  public String getCVCRate(TimerConfigurationType timerConfiguration)
  {
    String timerName = "CVC renewal check";

    // Check for configuration value
    if (timerConfiguration != null && timerConfiguration.getCertRenewal() != null)
    {
      TimerType certRenewal = timerConfiguration.getCertRenewal();
      if (certRenewal.getLength() != 0 && certRenewal.getUnit() != 0)
      {
        String rate = String.valueOf(getUnitOfTime(certRenewal.getUnit()) * certRenewal.getLength());
        logRateForTimer(timerName, rate);
        return rate;
      }
    }

    // Set default value to every hour
    String rate = String.valueOf(HOUR);
    logRateForTimer(timerName, rate);
    return rate;
  }

  @Bean
  public String getMasterDefectRate(TimerConfigurationType timerConfiguration)
  {
    String timerName = "Master and defect list renewal";

    // Check for configuration value
    if (timerConfiguration != null && timerConfiguration.getMasterAndDefectListRenewal() != null)
    {
      TimerType renewal = timerConfiguration.getMasterAndDefectListRenewal();
      if (renewal.getLength() != 0 && renewal.getUnit() != 0)
      {
        String rate = String.valueOf(getUnitOfTime(renewal.getUnit()) * renewal.getLength());
        logRateForTimer(timerName, rate);
        return rate;
      }
    }

    // Set default value to every 2 hours
    String rate = String.valueOf(2 * HOUR);
    logRateForTimer(timerName, rate);
    return rate;
  }

  @Bean
  public String getCrlRate(TimerConfigurationType timerConfiguration)
  {
    String timerName = "CRL renewal";

    // Check for configuration value
    if (timerConfiguration != null && timerConfiguration.getCrlRenewal() != null)
    {
      TimerType crlRenewal = timerConfiguration.getCrlRenewal();
      if (crlRenewal.getLength() != 0 && crlRenewal.getUnit() != 0)
      {
        String rate = String.valueOf(getUnitOfTime(crlRenewal.getUnit()) * crlRenewal.getLength());
        logRateForTimer(timerName, rate);
        return rate;
      }
    }

    // Set default value to every 2 hours
    String rate = String.valueOf(2 * HOUR);
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

  private void logRateForTimer(String timerName, String rate)
  {
    log.debug(" The timer '{}' will be executed every {} ms", timerName, rate);
  }
}
