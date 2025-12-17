/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.ecardid;

import de.governikus.eumw.poseidas.eidserver.convenience.session.SessionManager;


/**
 * Factory to get an object implementing ECardIDServerI from.
 *
 * @author tt
 */
public class ECardIDServerFactory
{

  private static final ECardIDServerFactory instance = new ECardIDServerFactory();

  private ECardIDServerFactory()
  {
    // nothing to do yet
  }

  /**
   * Singleton getter
   */
  public static ECardIDServerFactory getInstance()
  {
    return instance;
  }

  /**
   * Return an instance of ECardIDServer. Currently it will be always the same object.
   */
  public ECardIDServerI getCurrentServer()
  {
    return SessionManager.getInstance();
  }
}
