/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;



/**
 * Check that timer configurations are read correctly from configuration or default timers are used
 */
class TimerValuesTest
{


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
