/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import java.util.Calendar;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.poseidas.config.schema.TimerType;


/**
 * Check that timer configurations are read correctly from configuration or default timers are used
 */
class TimerValuesTest
{

  @Test
  void testGetDeltaBlacklistRate()
  {
    TimerValues timerValues = new TimerValues();
    String deltaBlacklistRate = timerValues.getDeltaBlacklistRate(null);
    final String defaultRate = String.valueOf(2 * TimerValues.HOUR);
    Assertions.assertEquals(defaultRate, deltaBlacklistRate);

    TimerConfigurationType timerConfiguration = new TimerConfigurationType();
    deltaBlacklistRate = timerValues.getDeltaBlacklistRate(timerConfiguration);
    Assertions.assertEquals(defaultRate, deltaBlacklistRate);

    TimerType blackListTimer = new TimerType();
    blackListTimer.setUnit(Calendar.MINUTE);
    blackListTimer.setLength(30);
    timerConfiguration.setBlacklistRenewal(blackListTimer);
    deltaBlacklistRate = timerValues.getDeltaBlacklistRate(timerConfiguration);
    Assertions.assertEquals(String.valueOf(30 * 60 * 1000), deltaBlacklistRate);
  }

  @Test
  void testGetCVCRate()
  {
    TimerValues timerValues = new TimerValues();
    String cvcRate = timerValues.getCVCRate(null);
    final String defaultRate = String.valueOf(TimerValues.HOUR);
    Assertions.assertEquals(defaultRate, cvcRate);

    TimerConfigurationType timerConfiguration = new TimerConfigurationType();
    cvcRate = timerValues.getCVCRate(timerConfiguration);
    Assertions.assertEquals(defaultRate, cvcRate);

    TimerType cvcTimer = new TimerType();
    cvcTimer.setUnit(Calendar.HOUR_OF_DAY);
    cvcTimer.setLength(10);
    timerConfiguration.setCertRenewal(cvcTimer);
    cvcRate = timerValues.getCVCRate(timerConfiguration);
    Assertions.assertEquals(String.valueOf(10 * 60 * 60 * 1000), cvcRate);
  }

  @Test
  void testGetMasterDefectRate()
  {
    TimerValues timerValues = new TimerValues();
    String timerRate = timerValues.getMasterDefectRate(null);
    final String defaultRate = String.valueOf(2 * TimerValues.HOUR);
    Assertions.assertEquals(defaultRate, timerRate);

    TimerConfigurationType timerConfiguration = new TimerConfigurationType();
    timerRate = timerValues.getMasterDefectRate(timerConfiguration);
    Assertions.assertEquals(defaultRate, timerRate);

    TimerType timerType = new TimerType();
    timerType.setUnit(Calendar.HOUR_OF_DAY);
    timerType.setLength(1);
    timerConfiguration.setMasterAndDefectListRenewal(timerType);
    timerRate = timerValues.getMasterDefectRate(timerConfiguration);
    Assertions.assertEquals(String.valueOf(60 * 60 * 1000), timerRate);
  }

  @Test
  void testGetCrlRate()
  {
    TimerValues timerValues = new TimerValues();
    String crlRate = timerValues.getCrlRate(null);
    final String defaultRate = String.valueOf(2 * TimerValues.HOUR);
    Assertions.assertEquals(defaultRate, crlRate);

    TimerConfigurationType timerConfiguration = new TimerConfigurationType();
    crlRate = timerValues.getCrlRate(timerConfiguration);
    Assertions.assertEquals(defaultRate, crlRate);

    TimerType crlTimer = new TimerType();
    crlTimer.setUnit(Calendar.MINUTE);
    crlTimer.setLength(30);
    timerConfiguration.setCrlRenewal(crlTimer);
    crlRate = timerValues.getCrlRate(timerConfiguration);
    Assertions.assertEquals(String.valueOf(30 * 60 * 1000), crlRate);
  }

  @Test
  void testInvalidTimerUnit()
  {
    TimerValues timerValues = new TimerValues();
    TimerConfigurationType timerConfigurationType = new TimerConfigurationType();
    TimerType timerType = new TimerType();
    timerType.setUnit(Calendar.MILLISECOND);
    timerType.setLength(10);
    timerConfigurationType.setCrlRenewal(timerType);

    IllegalArgumentException illegalArgumentException = Assertions.assertThrows(IllegalArgumentException.class,
                                                                                () -> timerValues.getCrlRate(timerConfigurationType));
    Assertions.assertEquals("Unsupported unit of time: " + Calendar.MILLISECOND, illegalArgumentException.getMessage());
  }

  @Test
  void testGetHumanReadableTime()
  {
    TimerValues timerValues = new TimerValues();
    String rate = Long.toString(0);
    Assertions.assertEquals("0 milliseconds", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(1);
    Assertions.assertEquals("1 milliseconds", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.SECOND + 500);
    Assertions.assertEquals("1500 milliseconds", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.SECOND);
    Assertions.assertEquals("1 seconds", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.SECOND * 30);
    Assertions.assertEquals("30 seconds", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.SECOND * 90);
    Assertions.assertEquals("90 seconds", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.SECOND * 60);
    Assertions.assertEquals("1 minutes", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.MINUTE * 30);
    Assertions.assertEquals("30 minutes", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.MINUTE * 90);
    Assertions.assertEquals("90 minutes", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.MINUTE * 60);
    Assertions.assertEquals("1 hours", timerValues.getHumanReadableRate(rate));

    rate = Long.toString(TimerValues.HOUR * 60);
    Assertions.assertEquals("60 hours", timerValues.getHumanReadableRate(rate));
  }
}
