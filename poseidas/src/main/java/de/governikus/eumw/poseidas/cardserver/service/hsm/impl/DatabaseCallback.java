/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

/**
 * Callback interface for database access from card_server.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface DatabaseCallback
{

  /**
   * Checks if this poseidas instance has the lock for the given key and if so, updates timestamp.
   * 
   * @param keyAlias alias of key, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if keyAlias <code>null</code> or empty
   * @return <code>true</code> if locked for this poseidas instance, <code>false</code> if not
   */
  public abstract boolean iHaveLock(String keyAlias);
}
