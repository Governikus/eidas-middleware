/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.impl;

import java.util.HashMap;
import java.util.Map;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.service.Service;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMServiceFactoryImpl;


public class ServiceRegistryImpl implements ServiceRegistry
{

  private Map<Class<? extends Service>, Service> serviceMap = null;

  public ServiceRegistryImpl()
  {
    super();
    serviceMap = new HashMap<>();
    serviceMap.put(HSMServiceFactory.class, new HSMServiceFactoryImpl());
  }

  @Override
  public <T extends Service> T getService(Class<T> serviceClass)
  {
    AssertUtil.notNull(serviceClass, "service class");
    Service service = serviceMap.get(serviceClass);
    T result = null;
    if (serviceClass.isInstance(service))
    {
      result = serviceClass.cast(service);
    }
    return result;
  }

  @Override
  public <T extends Service> void registerService(Class<T> serviceClass, T service)
  {
    AssertUtil.notNull(serviceClass, "service class");
    AssertUtil.notNull(service, "service");
    serviceMap.put(serviceClass, service);
  }

  @Override
  public <T extends Service> T unregisterService(Class<T> serviceClass)
  {
    return serviceClass.cast(serviceMap.remove(serviceClass));
  }

  @Override
  public <T extends Service> boolean serviceExists(Class<T> serviceClass)
  {
    return serviceMap.containsKey(serviceClass);
  }

  @Override
  public boolean isEmpty()
  {
    return serviceMap == null || serviceMap.isEmpty();
  }

  @Override
  public int size()
  {
    return serviceMap == null ? 0 : serviceMap.size();
  }
}
