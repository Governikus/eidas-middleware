/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service;

import de.governikus.eumw.poseidas.cardserver.service.impl.ServiceRegistryImpl;


public interface ServiceRegistry
{

  public <T extends Service> T getService(Class<T> serviceClass);

  public <T extends Service> boolean serviceExists(Class<T> serviceClass);

  public <T extends Service> void registerService(Class<T> serviceClass, T service);

  public <T extends Service> T unregisterService(Class<T> serviceClass);

  public int size();

  public boolean isEmpty();

  public static class Util
  {

    private static ServiceRegistry SINGLETON = null;

    private Util()
    {
      super();
    }

    public synchronized static ServiceRegistry getServiceRegistry()
    {
      if (SINGLETON == null)
      {
        SINGLETON = new ServiceRegistryImpl();
      }
      return SINGLETON;
    }
  }
}
