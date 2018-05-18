/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.core.WarmupListener;


/**
 * Holds the reference to a HSM service.
 * 
 * @author tautenhahn
 */
@Component
public class HSMServiceHolder implements WarmupListener
{

  private static final Log LOG = LogFactory.getLog(HSMServiceHolder.class);

  private HSMService service;

  @Autowired
  protected TerminalPermissionAO facade;

  public HSMServiceHolder()
  {
    /* Nothing to do */
  }

  private synchronized void setupService() throws HSMException
  {
    if (service == null)
    {
      service = de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry.Util.getServiceRegistry()
                                                                     .getService(HSMServiceFactory.class)
                                                                     .getHSMService(HSMService.NO_HSM);
    }
  }

  /**
   * trigger a logout (if necessary) to enable a new login.
   */
  public synchronized ManagementMessage stopHSMService()
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
    catch (HSMException e)
    {
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage(e.getMessage());
    }
    catch (IOException e)
    {
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage(e.getMessage());
    }
  }

  /**
   * Checks if the HSM service is alive and can be used with the current login.
   * 
   * @param allInstances <code>true</code> if all HSM instances in a cluster must be alive to yield the result
   *          "available", <code>false</code> if one single HSM is sufficient, ignored if no cluster is used
   * @return <code>true</code> if alive, <code>false</code> if not
   */
  public synchronized boolean isServiceAvailable(boolean allInstances)
  {
    try
    {
      return service != null && service.isAlive(allInstances);
    }
    catch (HSMException e)
    {
      return false;
    }
    catch (IOException e)
    {
      return false;
    }
  }

  /**
   * Checks if a HSM service is set.
   * 
   * @return <code>true</code> if service not <code>null</code>, <code>false</code> otherwise
   */
  public synchronized boolean isServiceSet()
  {
    return service != null;
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
        LOG.debug("Key " + alias + " is currently being changed in the HSM cluster");
        return;
      }
      LOG.debug("lock for key " + alias + " obtained");
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
        LOG.debug("Key " + alias + " is currently being changed in the HSM cluster");
        return;
      }
      LOG.debug("lock for key " + alias + " obtained");
      service.distributeKey(alias);
    }
  }

  @Override
  public void cooledDown()
  {
    stopHSMService();
  }

  @Override
  public List<ManagementMessage> warmingUp()
  {
    List<ManagementMessage> result = new ArrayList<>();
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
   * Gets set of HSMs found to be working incorrectly.
   * 
   * @return set of HSM addresses, empty if all HSM OK or none configured
   */
  public synchronized Set<String> getErroneousHSM()
  {
    if (this.service != null)
    {
      return this.service.getErroneousHSM();
    }
    return new TreeSet<>();
  }
}
