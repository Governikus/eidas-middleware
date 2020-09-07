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

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.server.pki.KeyLockChecker;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import lombok.extern.slf4j.Slf4j;


/**
 * This class activates the timer for various tasks <br>
 * The value for the timer rate are set via SpEL Bean Injection, the beans are generated
 * in @{@link TimerValues}.
 */
@Slf4j
@Component
public class ApplicationTimer
{

  private final PermissionDataHandling permissionDataHandling;

  private final KeyLockChecker keyLockChecker;

  public ApplicationTimer(PermissionDataHandling permissionDataHandling,
                          KeyLockChecker keyLockChecker)
  {
    this.permissionDataHandling = permissionDataHandling;
    this.keyLockChecker = keyLockChecker;
  }

  @Scheduled(fixedRateString = "#{@getFullBlacklistRate}", initialDelay = 30 * TimerValues.SECOND)
  public void renewFullBlackList()
  {
    permissionDataHandling.renewBlackList(false);
  }

  @Scheduled(fixedRateString = "#{@getDeltaBlacklistRate}", initialDelay = 2 * TimerValues.HOUR)
  public void renewDeltaBlackList()
  {
    permissionDataHandling.renewBlackList(true);
  }

  @Scheduled(fixedRateString = "#{@getCVCRate}", initialDelay = 5 * TimerValues.SECOND)
  public void checkForCVCRenewal()
  {
    permissionDataHandling.renewOutdatedCVCs();
  }

  @Scheduled(fixedRateString = "#{@getMasterDefectRate}", initialDelayString = "#{@getMasterDefectRate}")
  public void renewMasterDefectList()
  {
    permissionDataHandling.renewMasterAndDefectList();
  }

  @Scheduled(fixedRateString = "#{@getCrlRate}", initialDelay = 2 * TimerValues.HOUR)
  public void renewCRL()
  {
    CertificationRevocationListImpl.getInstance().renewCrls();
  }

  @Scheduled(fixedRateString = "#{@getKeyLockRate}", initialDelay = 30 * TimerValues.SECOND)
  public void checkKeyLocks()
  {
    keyLockChecker.checkKeyLocks();
  }
}
