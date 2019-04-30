/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.util.Date;
import java.util.List;

import javax.management.MBeanRegistration;
import javax.management.NotificationListener;


/**
 * Interface for handling the timers which trigger CVC, Master- Defect- and Blacklist renewal. The handling of
 * the permission data itself is delegated to class {@link PermissionDataHandling}.
 *
 * @author tautenhahn
 */

public interface TimerHandlingMBean extends NotificationListener, MBeanRegistration
{

  /**
   * Return String representation of all managed timer types.
   */
  public List<String> getTimerTypes();

  /**
   * Return date when the next timer of given type is scheduled
   *
   * @param type see return value of {@link #getTimerTypes()}
   */
  public Date getNextDate(String type);
}
