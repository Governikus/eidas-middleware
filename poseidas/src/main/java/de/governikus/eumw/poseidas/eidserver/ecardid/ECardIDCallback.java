/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.ecardid;

import java.io.Serializable;


/**
 * The server has to provide an implementor of this class to provide the session input data and retrieves the
 * eCardInformation, when the session is finalized ECardIDCallback
 * 
 * @author Alexander Funk
 * @author <a href="mail:hme@bos-bremen.de">Hauke Mehrtens</a>
 */
public interface ECardIDCallback extends Serializable
{

  /**
   * This method is called when the PAOS receiver gets a call with an unknown session id. This method should
   * return the SessionInput for this session ID if this session is known or null if it is unknown.
   * 
   * @param sessionId requested session ID
   * @return
   */
  public SessionInput getSessionInput(String sessionId);

  /**
   * This method is called when the Session is completed and the session result is provided to the original
   * initiator of this session.
   * 
   * @param sessinId given when this session was created
   * @param container the result informations
   */
  public void seteIDSessionComplete(String sessinId, EIDInfoContainer container);

}
