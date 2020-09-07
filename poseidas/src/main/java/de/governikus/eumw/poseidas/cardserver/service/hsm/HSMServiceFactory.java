/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm;

import de.governikus.eumw.poseidas.cardserver.service.Service;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;


/**
 * Interface for a factory to create different {@link HSMService}s.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface HSMServiceFactory extends Service
{

  /**
   * Gets interface to requested HSM and sets this as the default which will be returned by subsequent calls
   * to {@link #getHSMService()}.
   *
   * @param hsmType type of HSM, currently possible values are {@link HSMService#NO_HSM},
   *          {@link HSMService#PKCS11_HSM}
   * @return interface to HSM
   * @throws IllegalArgumentException if unknown type requested
   */
  public abstract HSMService getHSMService(int hsmType);

  /**
   * Gets interface to default HSM (default is the HSM which has been requested by {@link #getHSMService(int)}
   * or {@link #getHSMService(Class)} before; if such a call has not been made, using no HSM is default).
   *
   * @return interface to default HSM
   */
  public abstract HSMService getHSMService();

  /**
   * Gets interface to requested HSM and sets this as the default which will be returned by subsequent calls
   * to {@link #getHSMService()}.
   *
   * @param serviceClass class of {@link HSMService}
   * @return interface to HSM
   * @throws HSMException if requested HSM not available
   */
  public abstract HSMService getHSMService(Class<? extends HSMService> serviceClass) throws HSMException;
}
