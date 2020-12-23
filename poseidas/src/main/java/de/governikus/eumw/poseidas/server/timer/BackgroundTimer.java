/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.timer;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.server.pki.KeyLockChecker;


/**
 * This class activates the timer for not CVC related background tasks <br>
 * The value for the timer rate are set via SpEL Bean Injection, the beans are generated in @{@link TimerValues}.
 */
@Component
public class BackgroundTimer
{

  private final KeyLockChecker keyLockChecker;

  public BackgroundTimer(KeyLockChecker keyLockChecker)
  {
    this.keyLockChecker = keyLockChecker;
  }

  @Scheduled(fixedRateString = "#{@getKeyLockRate}", initialDelay = 30 * TimerValues.SECOND)
  public void checkKeyLocks()
  {
    keyLockChecker.checkKeyLocks();
  }
}
