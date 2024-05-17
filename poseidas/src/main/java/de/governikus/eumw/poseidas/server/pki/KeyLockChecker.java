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
import java.net.InetAddress;
import java.util.List;

import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import lombok.extern.slf4j.Slf4j;


/**
 * Utility class to check key locks in the database. Locks can be set when a HSM module is in use.
 */
@Component
@Slf4j
public class KeyLockChecker
{

  private final TerminalPermissionAO facade;

  private final HSMServiceHolder hsmServiceHolder;

  public KeyLockChecker(TerminalPermissionAO facade, HSMServiceHolder hsmServiceHolder)
  {
    this.facade = facade;
    this.hsmServiceHolder = hsmServiceHolder;
  }

  /**
   * Check for key locks and resolve them if possible.
   */
  public void checkKeyLocks()
  {
    try
    {
      log.debug("checking locks for {}", InetAddress.getLocalHost().toString());
      List<ChangeKeyLock> lockList = facade.getAllChangeKeyLocksByInstance(true);
      if (hsmServiceHolder.isServiceSet())
      {
        for ( ChangeKeyLock lock : lockList )
        {
          if (!hsmServiceHolder.isWorkingOnKey(lock.getKeyName()))
          {
            facade.releaseChangeKeyLock(lock);
            log.debug("lock for key {} released", lock.getKeyName());
          }
        }
      }
      List<ChangeKeyLock> foreignLockList = facade.getAllChangeKeyLocksByInstance(false);
      for ( ChangeKeyLock lock : foreignLockList )
      {
        if (facade.obtainChangeKeyLock(lock.getKeyName(), lock.getType()) != null)
        {
          if (lock.getType() == ChangeKeyLock.TYPE_DELETE)
          {
            hsmServiceHolder.deleteKey(lock.getKeyName());
            log.debug("lock for key {} stolen, deleting key", lock.getKeyName());
          }
          else
          {
            hsmServiceHolder.distributeKey(lock.getKeyName());
            log.debug("lock for key {} stolen, distributing key", lock.getKeyName());
          }
        }
      }
    }
    catch (HSMException | IOException e)
    {
      log.error("Problem during key lock check", e);
    }
  }
}
