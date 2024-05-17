/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import de.governikus.eumw.poseidas.server.pki.entities.CVCUpdateLock;
import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;


/**
 * Access to terminal permission data.
 *
 * @author tt
 */
public interface TerminalPermissionAO
{

  /**
   * Stores a new chain for this refID
   *
   * @param refID
   * @param chain
   */
  void storeCertInChain(String refID, byte[][] chain);

  /**
   * Create a new database entry
   *
   * @param refId
   */
  void create(String refId);

  /**
   * remove an existing database entry - attention!
   *
   * @param refID
   * @return true if there was an entry
   */
  boolean remove(String refID);

  /**
   * Store a created CVC request together with obtained certificate chain and (for test servers only) private key
   *
   * @param refID
   * @param messageId Id of the message that will be created to send that request to the BerCA
   * @param request
   * @param description - optional, leave null to keep the old one
   * @param chain
   * @param privKey null if private key is in the HSM
   */
  void storeCVCRequestCreated(String refID,
                              String messageId,
                              byte[] request,
                              byte[] description,
                              byte[][] chain,
                              byte[] privKey);

  /**
   * Store the information that a created CVC request has been sent
   *
   * @param refID
   */
  void storeCVCRequestSent(String refID);

  /**
   * Delete a CVC request from database regardless of its status.
   *
   * @param refID
   */
  void deleteCVCRequest(String refID);

  /**
   * Store an obtained CVC. As a side effect, the pending request is updated to state "received" or deleted in case it
   * was a subsequent request.
   *
   * @param refID
   * @param cvc
   * @param chain
   * @param certDescription
   */
  void storeCVCObtained(String refID, byte[] cvc, byte[][] chain, byte[] certDescription);

  /**
   * Store the public sector key. As a side effect, a pending request is considered to be finished and therefore
   * deleted.
   *
   * @param refID
   * @param publicSectorKey
   */
  void storePublicSectorKey(String refID, byte[] publicSectorKey);

  /**
   * Store an obtained master list
   *
   * @param refID
   * @param masterList
   */
  void storeMasterList(String refID, byte[] masterList);

  /**
   * Store an obtained defect list
   *
   * @param refID
   * @param defectList
   */
  void storeDefectList(String refID, byte[] defectList);

  /**
   * @param refID
   */
  TerminalPermission getTerminalPermission(String refID);

  /**
   * returns a Map with all refIDs as key and the expire dates of the CVCs as value.
   */
  Map<String, Date> getExpirationDates();

  /**
   * Create a lock for CVC updates for a specified service provider. Locks older than an hour are stolen.
   *
   * @param serviceProvider
   * @return lock if lock was obtained, null otherwise
   */
  CVCUpdateLock obtainCVCUpdateLock(String serviceProvider);

  /**
   * Release specified CVC update lock.
   *
   * @param toRelease lock to release
   * @return true if lock is released OK, false of not found or was stolen
   */
  boolean releaseCVCUpdateLock(CVCUpdateLock toRelease);

  /**
   * Return the permission object which has the pending certificate request with given messageID.
   *
   * @param messageID
   */
  TerminalPermission getTerminalPermissionByMessage(String messageID);

  /**
   * Store information that an error occurred which requires administrator interaction.
   *
   * @param refID
   * @param additionalInfo free string describing the problem
   */
  void storeCVCObtainedError(String refID, String additionalInfo);

  /**
   * Tries to obtain a "change key" lock.
   *
   * @param keyName name of key to be locked, <code>null</code> or empty not permitted
   * @param type lock type, must be one of {@link ChangeKeyLock#TYPE_DELETE} or {@link ChangeKeyLock#TYPE_DISTRIBUTE}
   * @return lock, <code>null</code> if unable to obtain lock
   * @throws IllegalArgumentException if keyName <code>null</code> or empty or if unknown lock type given
   */
  ChangeKeyLock obtainChangeKeyLock(String keyName, int type);

  /**
   * Releases a "change key" lock.
   *
   * @param toRelease lock to be released, <code>null</code> not permitted
   * @return <code>true</code> if successfully released, <code>false</code> otherwise
   */
  boolean releaseChangeKeyLock(ChangeKeyLock toRelease);

  /**
   * Gives up ownership of a "change key" lock, but does not delete it since its associated task must still be
   * completed. After completion of this method, everyone can take over the lock.
   *
   * @param toRelease lock to be released, <code>null</code> not permitted
   * @return <code>true</code> if successfully released, <code>false</code> otherwise
   */
  boolean releaseChangeKeyLockOwner(ChangeKeyLock toRelease);

  /**
   * Retrieves all "change key" locks split by their holder.
   *
   * @param own <code>true</code> for all locks hold by this instance, <code>false</code> for all locks hold by other
   *          instances
   * @return list of locks, possibly empty
   */
  List<ChangeKeyLock> getAllChangeKeyLocksByInstance(boolean own);

  /**
   * Checks if a lock for a given key name exists and is a lock for distribution.
   *
   * @param keyName key name
   * @return <code>true</code> if existing, <code>false</code> otherwise
   */
  boolean changeKeyLockExists(String keyName);

  /**
   * Checks if this poseidas instance owns the "change key" lock for a given key.
   *
   * @param keyName name of key, <code>null</code> or empty not permitted
   * @return <code>true</code> if lock existing and held by this instance, <code>false</code> otherwise
   * @throws IllegalArgumentException if keyName <code>null</code> or empty
   */
  boolean iHaveLock(String keyName);

  /**
   * Archives an old CVC.
   *
   * @param alias alias of key, <code>null</code> or empty not permitted
   * @param cvcData cvc data, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   */
  void archiveCVC(String alias, byte[] cvcData);

  /**
   * Archives an old private key.
   *
   * @param alias alias of key, <code>null</code> or empty not permitted
   * @param keyData key data, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   */
  void archiveKey(String alias, byte[] keyData);


  /**
   * Returns a list of the refIDs of all TerminalPermissions.
   *
   * @return list of the refIDs of all TerminalPermissions
   */
  List<String> getTerminalPermissionRefIDList();

  /**
   * Getter
   *
   * @param refID RefId of a {@link TerminalPermission}
   * @return rscChrId, <code>null</code> if not found
   */
  Integer getCurrentRscChrId(String refID);

  /**
   * Getter
   *
   * @param refID RefId of a {@link TerminalPermission}
   * @return rscChrId, <code>null</code> if not found
   */
  Integer getPendingRscChrId(String refID);

  /**
   * Get status of pending RSC.
   *
   * @param refID refID of a {@link TerminalPermission}
   * @return status, <code>null</code> if not found
   */
  RequestSignerCertificate.Status getPendingRscStatus(String refID);

  /**
   * Set status of pending RSC to failed.
   *
   * @param refID refID of a {@link TerminalPermission}
   */
  void setPendingRscStatusFailed(String refID);

  /**
   * Changes the pending Request Signer Certificate to the current one.
   *
   * @param refID RefId of a {@link TerminalPermission}
   * @param deletePendingCertificateRequest Any pending certificate request must be deleted if the RSC was renewed using
   *          the DVCA interface. It must not be deleted if the pending RSC was used during a CVC renewal.
   */
  void makePendingRscToCurrentRsc(String refID, boolean deletePendingCertificateRequest);

  /**
   * Sets the pending Request Signer Certificate.
   *
   * @param refID RefId of a {@link TerminalPermission}
   * @throws TerminalPermissionNotFoundException
   */
  void setPendingRequestSignerCertificate(String refID, RequestSignerCertificate pendingRequestSignerCertificate)
    throws TerminalPermissionNotFoundException;

  /**
   * <b>Attention:</b> Only use this method if you are sure that the RSC is not in an HSM. Otherwise, use
   * {@link RequestSignerCertificateService#getRequestSignerCertificate(String, boolean)} instead.
   * <p/>
   * Get the request signer certificate.
   *
   * @param refID RefId of a {@link TerminalPermission}
   * @param current <code>true</code> for the current certificate, <code>false</code> for pending
   * @return certificate, <code>null</code> if not present
   */
  X509Certificate getRequestSignerCertificate(String refID, boolean current);

  /**
   * Get the request signer key.
   *
   * @param refID RefId of a {@link TerminalPermission}
   * @param current <code>true</code> for the current key, <code>false</code> for pending
   * @return key, <code>null</code> if not present
   */
  byte[] getRequestSignerKey(String refID, boolean current);


  boolean isPublicClient(String entityId);

  /**
   * Get the request signer certificate holder for a given refID.
   *
   * @param refID the refID
   * @return the rsc holder
   */
  String getRequestSignerCertificateHolder(String refID);

  /**
   * Set the request signer certificate holder for a given refID.
   *
   * @param refID the refID
   * @param holder the new holder to set
   * @throws TerminalPermissionNotFoundException
   */
  void setRequestSignerCertificateHolder(String refID, String holder) throws TerminalPermissionNotFoundException;

  /**
   * Increase sequence counter for next request.
   *
   * @param refId the refID
   */
  void increaseSequenceNumber(String refId);

  /**
   * Deletes the pending Request Signer Certificate.
   *
   * @param refID RefId of a {@link TerminalPermission}
   * @throws TerminalPermissionNotFoundException
   */
  void deletePendingRequestSignerCertificate(String refID) throws TerminalPermissionNotFoundException;

  /**
   * Sets the status of the automatic CVC renewal. If an CVC renewal was successful the value is {@code false}. Only
   * when an automatic CVC renewal triggered by the {@link de.governikus.eumw.poseidas.server.timer.CvcRenewalTimer} was
   * not successfull the value is {@code true}.
   *
   * @param refID the ref ID of the {@link TerminalPermission} for which the status should be set
   * @param isCvcRenewalFailed value of the CVC renewal result
   */
  void setAutomaticCvcRenewFailed(String refID, boolean isCvcRenewalFailed);

  /**
   * Set the status of the automatic RSC renewal.
   *
   * @param refID the refID of the {@link TerminalPermission} for which the status should be set
   * @param cause description of the failure, <code>null</code> if OK
   */
  void setAutomaticRscRenewFailed(String refID, String cause);

  /**
   * Get the status of the automatic RSC renewal.
   *
   * @param refID the refID of the {@link TerminalPermission} for which the status should be retrieved
   * @return <code>null</code> if OK, content otherwise
   */
  String getAutomaticRscRenewFailed(String refID);
}
