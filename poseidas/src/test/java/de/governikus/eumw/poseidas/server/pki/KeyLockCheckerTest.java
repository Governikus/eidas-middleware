/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;


import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;


@ExtendWith(MockitoExtension.class)
class KeyLockCheckerTest
{

  @Mock
  TerminalPermissionAO facade;

  @Mock
  HSMServiceHolder hsmServiceHolder;

  @Test
  void testCheckKeyLocks() throws IOException, HSMException
  {
    // Create commonly used key names
    String firstKey = "firstKey";
    String secondKey = "secondKey";
    String thirdKey = "thirdKey";
    String fourthKey = "fourthKey";
    String fifthKey = "fifthKey";

    // Prepare ChangeKeyLocks for so called own instance
    Map<String, ChangeKeyLock> ownKeyLockList = new HashMap<>();
    ownKeyLockList.put(firstKey, new ChangeKeyLock(firstKey, "localhost", System.currentTimeMillis(), 0));
    ownKeyLockList.put(secondKey, new ChangeKeyLock(secondKey, "localhost", System.currentTimeMillis(), 1));

    // Prepare ChangeKeyLocks for so called other instances
    Map<String, ChangeKeyLock> otherKeyLockList = new HashMap<>();
    otherKeyLockList.put(thirdKey, new ChangeKeyLock(thirdKey, "otherhost", System.currentTimeMillis(), 0));
    otherKeyLockList.put(fourthKey, new ChangeKeyLock(fourthKey, "otherhost", System.currentTimeMillis(), 1));
    otherKeyLockList.put(fifthKey, new ChangeKeyLock(fifthKey, "otherhost", System.currentTimeMillis(), 1));

    // Make mock return different lists of ChangeKeyLocks depending on the parameter
    Mockito.doReturn(new ArrayList<>(ownKeyLockList.values()))
           .when(facade)
           .getAllChangeKeyLocksByInstance(true);
    Mockito.doReturn(new ArrayList<>(otherKeyLockList.values()))
           .when(facade)
           .getAllChangeKeyLocksByInstance(false);

    // Make mock return correct ChangeKeyLocks when obtainChangeKeyLock is called with different parameters
    Mockito.doReturn(otherKeyLockList.get(thirdKey)).when(facade).obtainChangeKeyLock(thirdKey, 0);
    Mockito.doReturn(otherKeyLockList.get(fourthKey)).when(facade).obtainChangeKeyLock(fourthKey, 1);
    Mockito.doReturn(null).when(facade).obtainChangeKeyLock(fifthKey, 1);

    // Make mock return different values depending on the parameter
    Mockito.when(hsmServiceHolder.isServiceSet()).thenReturn(true);
    Mockito.doReturn(false).when(hsmServiceHolder).isWorkingOnKey(firstKey);
    Mockito.doReturn(true).when(hsmServiceHolder).isWorkingOnKey(secondKey);

    // Create the KeyLockChecker and execute the method
    KeyLockChecker keyLockChecker = new KeyLockChecker(facade, hsmServiceHolder);
    keyLockChecker.checkKeyLocks();

    // Verify that the correct ChangeKeyLocks are released
    Mockito.verify(facade).releaseChangeKeyLock(ownKeyLockList.get(firstKey));
    Mockito.verify(facade, Mockito.never()).releaseChangeKeyLock(ownKeyLockList.get(secondKey));

    // Verify that the correct ChangeKeyLocks are deleted or distributed
    Mockito.verify(hsmServiceHolder).deleteKey(thirdKey);
    Mockito.verify(hsmServiceHolder).distributeKey(fourthKey);
    Mockito.verify(hsmServiceHolder, Mockito.never()).deleteKey(fifthKey);
    Mockito.verify(hsmServiceHolder, Mockito.never()).distributeKey(fifthKey);
  }

}
