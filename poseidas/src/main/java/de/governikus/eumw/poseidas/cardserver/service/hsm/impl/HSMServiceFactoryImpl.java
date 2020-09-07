/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

import java.lang.reflect.Method;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;


/**
 * Implementation of {@link HSMServiceFactory}.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class HSMServiceFactoryImpl implements HSMServiceFactory
{

  /**
   * Constructor.
   */
  public HSMServiceFactoryImpl()
  {
    super();
  }

  /**
   * Initialization and setter for default HSM type.
   *
   * @param hsmType new default HSM type
   * @throws HSMException if {@link UtimacoHSMService} requested but not available
   */
  private static void init(int hsmType)
  {
    ServiceRegistry sr = ServiceRegistry.Util.getServiceRegistry();

    // BOS local service available at all times
    if (!sr.serviceExists(BOSHSMSimulatorService.class))
    {
      BOSHSMSimulatorService bosService = BOSHSMSimulatorService.getInstance();
      sr.registerService(BOSHSMSimulatorService.class, bosService);
    }

    if (hsmType == HSMService.PKCS11_HSM)
    {
      if (!sr.serviceExists(PKCS11HSMService.class))
      {
        PKCS11HSMService pkcs11HSM = PKCS11HSMService.getInstance();
        sr.registerService(PKCS11HSMService.class, pkcs11HSM);
      }
      sr.registerService(HSMService.class, sr.getService(PKCS11HSMService.class));
    }
    else if (hsmType == HSMService.NO_HSM)
    {
      sr.registerService(HSMService.class, sr.getService(BOSHSMSimulatorService.class));
    }
  }

  /** {@inheritDoc} */
  @Override
  public HSMService getHSMService(int hsmType)
  {
    if (hsmType != HSMService.NO_HSM && hsmType != HSMService.PKCS11_HSM)
    {
      throw new IllegalArgumentException("unknown type of HSM requested");
    }
    init(hsmType);
    return ServiceRegistry.Util.getServiceRegistry().getService(HSMService.class);
  }

  /** {@inheritDoc} */
  @Override
  public HSMService getHSMService()
  {
    ServiceRegistry sr = ServiceRegistry.Util.getServiceRegistry();
    if (!sr.serviceExists(HSMService.class))
    {
      init(HSMService.NO_HSM);
    }
    return sr.getService(HSMService.class);
  }

  /** {@inheritDoc} */
  @Override
  public HSMService getHSMService(Class<? extends HSMService> serviceClass) throws HSMException
  {
    AssertUtil.notNull(serviceClass, "HSM service class");
    ServiceRegistry sr = ServiceRegistry.Util.getServiceRegistry();

    if (!sr.serviceExists(serviceClass))
    {
      try
      {
        Method getInstance = serviceClass.getMethod("getInstance");
        HSMService service = (HSMService)getInstance.invoke(null);
        sr.registerService((Class<HSMService>)serviceClass, service);
        sr.registerService(HSMService.class, service);
      }
      catch (Exception e)
      {
        throw new HSMException(e);
      }
    }
    return sr.getService(serviceClass);
  }
}
