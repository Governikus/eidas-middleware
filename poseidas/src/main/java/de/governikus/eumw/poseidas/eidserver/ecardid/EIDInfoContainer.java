/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.eidserver.ecardid;

import java.util.Map;

import de.governikus.eumw.poseidas.eidmodel.data.EIDKeys;
import de.governikus.eumw.poseidas.eidserver.convenience.EIDInfoResult;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * EIDInfoContainer Container for the results of the authentication process will contain any informations received and
 * authenticated from the card.
 *
 * @author Alexander Funk
 */
public interface EIDInfoContainer
{

  /**
   * The validation result of the nPA used in SAML Response.
   */
  public enum EIDStatus
  {
    VALID, FAILED, EXPIRED, REVOKED, NOT_AUTHENTIC
  }

  /**
   * the eIDprocess may fail, check this before accessing the result.
   *
   * @return
   */
  public boolean hasErrors();


  /**
   * informations about failure
   *
   * @return will return null if hasErrors() returns false
   */
  public Result getResult();

  /**
   * gets the map with the information available
   *
   * @return
   */
  public Map<EIDKeys, EIDInfoResult> getInfoMap();

  /**
   * Returns the validation status see {@link EIDStatus}
   */
  public EIDStatus getStatus();
}
