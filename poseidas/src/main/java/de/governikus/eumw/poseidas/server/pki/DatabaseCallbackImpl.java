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

import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.DatabaseCallback;


/**
 * Implementation of {@link DatabaseCallback} for the HSM service.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class DatabaseCallbackImpl implements DatabaseCallback
{

  /**
   * Database access.
   */
  private final TerminalPermissionAO facade;

  /**
   * Constructor.
   * 
   * @param tpa database access
   */
  DatabaseCallbackImpl(TerminalPermissionAO tpa)
  {
    super();
    this.facade = tpa;
  }

  /** {@inheritDoc} */
  @Override
  public boolean iHaveLock(String arg0)
  {
    return this.facade.iHaveLock(arg0);
  }
}
