/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.core;

import java.io.Serializable;


/**
 * This interface must be implemented by Session which should be stored in the session store and be management by the
 * AuthenticationSessionManager.
 *
 * @author mehrtens
 */
public interface StoreableSession extends Serializable
{

  /**
   * Returns the time in Milliseconds when this Session was created. This is needed to remove old sessions form the
   * store.
   */
  long getCreationTime();

  /**
   * Returns the ID of this session. It must be Unique over all sessions of this type.
   */
  String getSessionId();

  /**
   * The ID of the request used to create this Session. This must be unique over all managed entries. Will return null
   * if the session does not have a request ID.<br/>
   * Needed when an out-dated session is deleted automatically and the requestID set is updated.
   */
  String getRequestId();

  /**
   * This method gets called when this session gets removed from the session store. Do some cleanup or accounting stuff
   * here.
   *
   * @param cleanup if set to true this was called while the old sessions are getting removed.
   */
  void removed(boolean cleanup);

}
