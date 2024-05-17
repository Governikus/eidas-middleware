/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.util.Map;

import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;


/**
 * Interface for permission data handling which can be use from a client without extending the class path.
 * <p>
 * <b> when doing any change see second class </b>
 * </p>
 *
 * @author tt
 * @author Hauke Mehrtens
 */
public interface PermissionDataHandlingMBean
{

  /**
   * Remove a set of permission data from the database
   *
   * @param cvcRefId
   */
  ManagementMessage removePermissionData(String cvcRefId);

  /**
   * Returns informations about the Permission data object. Use AdminPoseidasConstants.VALUE_PERMISSION_DATA_* to access
   * the map.
   *
   * @param cvcRefId
   * @param withBlkNumber include the number of entries in the blacklist, this could take some more time.
   */
  Map<String, Object> getPermissionDataInfo(String cvcRefId, boolean withBlkNumber);

  /**
   * Request a new CVC for each service provider where the current CVC will expire within the time specified in
   * configuration. When called in parallel on several servers using the same database, this method will renew each CVC
   * only once.
   */
  void renewOutdatedCVCs();

  /**
   * Request a new terminal certificate to access the nPA with. The system will generate and store a key pair, create a
   * certificate request, send it and store the results.
   *
   * @param entityID defines the service provider to work for
   * @param countryCode
   * @param chrMnemonic
   * @return status message
   */
  ManagementMessage requestFirstTerminalCertificate(String entityID,
                                                    String countryCode,
                                                    String chrMnemonic,
                                                    int sequenceNumber);


  /**
   * Create a database entry in which terminal certificates can be stored.
   *
   * @param cvcRefId unique ID of the entry
   * @return status message
   */
  ManagementMessage createTerminalPermissionEntry(String cvcRefId);

  /**
   * Trigger a subsequent certificate request manually for one service provider.
   *
   * @param entityID
   * @return "OK" or "internal error"
   */
  ManagementMessage triggerCertRenewal(String entityID);

  /**
   * Check whether the configuration is sufficiently complete for requesting an CVC.
   *
   * @param entityID
   * @return no message in success case.
   */
  ManagementMessage checkReadyForFirstRequest(String entityID);

  /**
   * Trigger renewal of all existing black lists. Furthermore, for all entries where a certificate is obtained but
   * getting the blacklist failed, the missing blacklist and sector public key is requested. <br>
   * Normally, this method is triggered by a timer. Call it only for test purposes!
   *
   * @param delta flag indicating a delta request
   */
  void renewBlackList(boolean delta);

  /**
   * Trigger a renewal of the blacklist assosiated with the given entityID.
   *
   * @return ok, if everything was ok or an error message.
   */
  ManagementMessage renewBlackList(String entityID);

  /**
   * Trigger renewal of all master and defect lists.
   */
  void renewMasterAndDefectList();

  /**
   * Trigger renewal of the master and defect lists with the given entityID.
   *
   * @return ok, if everything was ok or an error message.
   */
  ManagementMessage renewMasterAndDefectList(String entityID);

  /**
   * Returns the CVC description for the given CvcRefId. In case of an error it returns an ManagementMessage.
   *
   * @param cvcRefId
   * @return CVC description
   */
  byte[] getCvcDescription(String cvcRefId) throws GovManagementException;

  /**
   * Checks if the PA service for a given entityID is reachable.
   *
   * @param entityID
   * @return <code>true</code> if reachable, <code>false</code> if not
   */
  boolean pingPAService(String entityID);

  /**
   * Checks if the RI service for a given entityID is reachable.
   *
   * @param entityID
   * @return <code>true</code> if reachable, <code>false</code> if not
   */
  boolean pingRIService(String entityID);

}
