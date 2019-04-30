/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.core;

import java.util.List;

import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;


/**
 * Listener to be notified each time the poseidas server warms up or goes offline.
 *
 * @author tautenhahn
 */
public interface WarmupListener
{

  /**
   * called when system state of poseidas is about to change from offline to warm
   *
   * @return messages produced by a self test
   */
  public List<ManagementMessage> warmingUp();

  /**
   * called after the system state of poseidas changed from warm or hot to offline
   */
  public void cooledDown();
}
