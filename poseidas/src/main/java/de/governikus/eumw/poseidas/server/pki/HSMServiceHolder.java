/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMConfiguration;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.PKCS11HSMConfiguration;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.core.WarmupListener;
import lombok.extern.slf4j.Slf4j;


/**
 * Holds the reference to a HSM service.
 *
 * @author tautenhahn
 */
@Component
@Slf4j
public class HSMServiceHolder implements WarmupListener
{

  private HSMService service;

  private final int hsmType;

  private final HSMConfiguration hsmConfig;

  @Autowired
  protected TerminalPermissionAO facade;

  @Value("${hsm.keys.delete:30}")
  private int deleteOldKeys;

  @Value("${hsm.keys.archive:false}")
  private boolean archiveOldKeys;

  public HSMServiceHolder(@Value("${hsm.type:}") String hsmTypeStr,
                          @Value("${pkcs11.config:}") String pathToPkcs11Config,
                          @Value("${pkcs11.passwd:}") String pkcs11Passwd)
  {
    if ("PKCS11".equalsIgnoreCase(hsmTypeStr))
    {
      hsmType = HSMService.PKCS11_HSM;
      hsmConfig = new PKCS11HSMConfiguration(pathToPkcs11Config, pkcs11Passwd);
    }
    else
    {
      hsmType = HSMService.NO_HSM;
      hsmConfig = null;
    }
    warmingUp();
  }

  private synchronized void setupService()
  {
    if (service == null)
    {
      service = de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry.Util.getServiceRegistry()
                                                                                   .getService(HSMServiceFactory.class)
                                                                                   .getHSMService(hsmType);
    }
  }

  /**
   * get the HSM service and perform a login.
   *
   * @return status message
   */
  private synchronized ManagementMessage startHSMService()
  {
    setupService();
    if (!service.isInitialized())
    {
      try
      {
        service.init(hsmConfig);
      }
      catch (HSMException e)
      {
        return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("HSM init failed: " + e);
      }
    }
    return GlobalManagementCodes.OK.createMessage();
  }

  /**
   * trigger a logout (if necessary) to enable a new login.
   */
  private synchronized ManagementMessage stopHSMService()
  {
    try
    {
      if (service != null)
      {
        service.logout();
        service = null;
      }
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (IllegalStateException e)
    {
      if ("HSM service not initialized".equals(e.getMessage()))
      {
        return GlobalManagementCodes.OK.createMessage();
      }
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage(e.getMessage());
    }
    catch (HSMException | IOException e)
    {
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage(e.getMessage());
    }
    catch (UnsupportedOperationException e)
    {
      // expected for operation without HSM, continue
      service = null;
      return GlobalManagementCodes.OK.createMessage();
    }
  }

  /**
   * Checks if the HSM service is alive and can be used with the current login.
   *
   * @param allInstances <code>true</code> if all HSM instances in a cluster must be alive to yield the result
   *          "available", <code>false</code> if one single HSM is sufficient, ignored if no cluster is used
   * @return <code>true</code> if alive, <code>false</code> if not
   */
  private synchronized boolean isServiceAvailable(boolean allInstances)
  {
    try
    {
      return service != null && service.isAlive(allInstances);
    }
    catch (HSMException | IOException e)
    {
      return false;
    }
  }

  /**
   * Checks if a HSM service is set.
   *
   * @return <code>true</code> if service not <code>null</code>, <code>false</code> otherwise
   */
  synchronized boolean isServiceSet()
  {
    return service != null;
  }

  /**
   * If service is alive and a positive number given, delete all keys which have expired since the given number of days.
   *
   * @param deleteAfterDays days after which to delete a key
   * @param archive <code>true</code> for archiving old keys in database
   * @throws HSMException
   * @throws IOException
   */
  synchronized void deleteOutdatedKeys() throws HSMException, IOException
  {
    if (deleteOldKeys < 1 || !isServiceAvailable(true))
    {
      return;
    }
    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DAY_OF_MONTH, -deleteOldKeys);
    Date keepLimit = cal.getTime();
    for ( String alias : service.getAliases() )
    {
      log.debug("Checking alias {}", alias);
      Date reference = null;
      try
      {
        reference = service.getExpirationDate(alias);
      }
      catch (UnsupportedOperationException e)
      {
        try
        {
          reference = service.getGenerationDate(alias);
        }
        catch (UnsupportedOperationException e2)
        {
          // do not delete if no date is known
          return;
        }
      }
      if (reference.before(keepLimit))
      {
        log.debug("Trying to delete key {}", alias);
        ChangeKeyLock lock = facade.obtainChangeKeyLock(alias, ChangeKeyLock.TYPE_DELETE);
        if (lock == null)
        {
          log.debug("Key {} is currently being changed in the HSM cluster", alias);
          continue;
        }
        log.debug("lock for key {} obtained", alias);
        if (archiveOldKeys)
        {
          try
          {
            byte[] keyData = service.exportKey(alias);
            this.facade.archiveKey(alias, keyData);
            log.debug("key {} successfully archived", alias);
          }
          catch (UnsupportedOperationException e)
          {
            // possible until implemented for every HSM
            if (log.isDebugEnabled())
            {
              log.debug("key " + alias + " not archived due to exception", e);
            }
          }
        }
        service.deleteKey(alias);
      }
      else
      {
        log.debug("Not deleting key {} - still young enough", alias);
      }
    }
  }

  /**
   * Delete a key specified by given alias.
   *
   * @param alias
   * @throws IOException
   * @throws HSMException
   */
  synchronized void deleteKey(String alias) throws IOException, HSMException
  {
    setupService();
    if (service.isInitialized())
    {
      ChangeKeyLock lock = facade.obtainChangeKeyLock(alias, ChangeKeyLock.TYPE_DELETE);
      if (lock == null)
      {
        log.debug("Key {} is currently being changed in the HSM cluster", alias);
        return;
      }
      log.debug("lock for key {} obtained", alias);
      service.deleteKey(alias);
    }
  }

  /**
   * Distribute a key specified by given alias.
   *
   * @param alias
   * @throws IOException
   * @throws HSMException
   */
  synchronized void distributeKey(String alias) throws IOException, HSMException
  {
    setupService();
    if (service.isInitialized())
    {
      ChangeKeyLock lock = facade.obtainChangeKeyLock(alias, ChangeKeyLock.TYPE_DISTRIBUTE);
      if (lock == null)
      {
        log.debug("Key {} is currently being changed in the HSM cluster", alias);
        return;
      }
      log.debug("lock for key {} obtained", alias);
      service.distributeKey(alias);
    }
  }

  @Override
  public void cooledDown()
  {
    stopHSMService();
  }

  @Override
  public final List<ManagementMessage> warmingUp()
  {
    List<ManagementMessage> result = new ArrayList<>();
    if (!isServiceAvailable(false))
    {
      result.add(startHSMService());
      if (!isServiceAvailable(false))
      {
        result.add(GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("No HSM active"));
      }
    }
    return result;
  }

  /**
   * Checks if HSM is currently working on a given key.
   *
   * @param keyName name of key to be checked
   * @return <code>true</code> if key worked on, <code>false</code> if not or if no HSM configured
   */
  synchronized boolean isWorkingOnKey(String keyName)
  {
    if (this.service != null)
    {
      return this.service.isKeyBeingModified(keyName);
    }
    return false;
  }

  /**
   * Gets the HSM based keystore if possible.
   *
   * @return keystore, <code>null</code> if not available
   */
  public synchronized KeyStore getKeyStore()
  {
    if (service != null)
    {
      return service.getKeyStore();
    }
    return null;
  }
}
