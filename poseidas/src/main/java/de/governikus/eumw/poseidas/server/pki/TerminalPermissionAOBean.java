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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Lists;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.server.pki.PendingCertificateRequest.Status;
import lombok.extern.slf4j.Slf4j;


/**
 * Access to terminal permission data. Use
 * de.bos_bremen.gov2.jca_provider.ocf.asn1.cvc.CertificateRequestGenerator for getting the data!
 *
 * @author tt
 */
@Repository
@Transactional
@Slf4j
public class TerminalPermissionAOBean implements TerminalPermissionAO
{

  private static final int MAX_DB_ARGS = 5000;

  private static final int DEFAULT_BATCH_SIZE = 1000;

  public static final String SECTOR_ID = "sectorID";

  @Autowired
  private ApplicationContext applicationContext;

  @PersistenceContext
  EntityManager entityManager;

  /** {@inheritDoc} */
  @Override
  @Transactional
  public void importData(String refID,
                         byte[] cvc,
                         byte[] cvcDescription,
                         byte[] cvcPrivateKey,
                         byte[] riKey1,
                         byte[] psKey,
                         byte[][] chain,
                         byte[] masterList,
                         byte[] defectList)
  {
    boolean merge = true;
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    if (data == null)
    {
      data = new TerminalPermission(refID);
      entityManager.persist(data);
      merge = false;
    }
    if (cvc != null)
    {
      data.setCvc(cvc);
    }
    if (cvcDescription != null)
    {
      data.setCvcDescription(cvcDescription);
    }
    if (cvcPrivateKey != null)
    {
      data.setCvcPrivateKey(cvcPrivateKey);
    }
    if (riKey1 != null)
    {
      data.setRiKey1(riKey1);
    }
    if (psKey != null)
    {
      data.setPSKey(psKey);
    }
    if (defectList != null)
    {
      data.setDefectList(defectList);
      data.setDefectListStoreDate(new Date());
    }
    if (masterList != null)
    {
      data.setMasterList(masterList);
      data.setMasterListStoreDate(new Date());
    }
    if (chain != null && chain.length != 0)
    {
      for ( CertInChain entry : data.getChain() )
      {
        entityManager.remove(entry);
      }
      data.getChain().clear();
      // do not set notOnOrAfter - we do not want the renewal timer to get this entry
      for ( int i = 0 ; i < chain.length ; i++ )
      {
        CertInChain entry = new CertInChain(data, new CertInChainPK(refID, i), chain[i]);
        entityManager.persist(entry);
        data.getChain().add(entry);
      }
    }
    if (merge)
    {
      entityManager.merge(data);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void storeCertInChain(String refID, byte[][] chain)
  {
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    if (chain != null)
    {
      storeCertInChain(chain, data);
    }
  }

  /**
   * Store a new chain for this terminal
   *
   * @param chain the chain to be stored
   * @param data the terminal reference
   */
  @Transactional
  public void storeCertInChain(byte[][] chain, TerminalPermission data)
  {
    Set<CertInChain> newChain = new HashSet<>();
    for ( int i = 0 ; i < chain.length ; i++ )
    {
      byte[] cert = chain[i];
      CertInChain c = new CertInChain(data, new CertInChainPK(data.getRefID(), i), cert);
      newChain.add(c);
    }
    Map<CertInChainPK, CertInChain> oldChain = new HashMap<>();
    for ( CertInChain entry : data.getChain() )
    {
      oldChain.put(entry.getKey(), entry);
    }
    for ( CertInChain entry : newChain )
    {
      CertInChain oldEntry = oldChain.get(entry.getKey());
      if (oldEntry == null)
      {
        data.getChain().add(entry);
        entityManager.persist(entry);
      }
      else
      {
        oldEntry.setData(entry.getData());
        entityManager.merge(oldEntry);
        oldChain.remove(oldEntry.getKey());
      }
    }
    for ( CertInChain entry : oldChain.values() )
    {
      data.getChain().remove(entry);
      entityManager.remove(entry);
    }
  }

  /** {@inheritDoc} */
  @Override
  public TerminalPermission getTerminalPermission(String refID)
  {
    TerminalPermission result = entityManager.find(TerminalPermission.class, refID);
    // pre-fetch the chain before we detach the Entity
    if (result != null)
    {
      result.getChain().size();
      result.getPendingCertificateRequest();
    }
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public Map<String, Date> getExpirationDates()
  {
    Map<String, Date> result = new HashMap<>();
    TypedQuery<TerminalPermission> query = entityManager.createNamedQuery("getTerminalPermissionList",
                                                                          TerminalPermission.class);
    for ( TerminalPermission permission : query.getResultList() )
    {
      if (permission.getNotOnOrAfter() != null)
      {
        result.put(permission.getRefID(), permission.getNotOnOrAfter());
      }
    }
    return result;
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public CVCUpdateLock obtainCVCUpdateLock(String serviceProvider)
  {
    long now = System.currentTimeMillis();
    CVCUpdateLock lock = entityManager.find(CVCUpdateLock.class, serviceProvider);
    if (lock == null)
    {
      lock = new CVCUpdateLock(serviceProvider, now);
      entityManager.persist(lock);
    }
    else
    {
      // accepted maximum for a single CVC update: ten minutes
      if (lock.getLockedAt() > now - 1000L * 60 * 10)
      {
        return null;
      }
      log.error("{}: Found out-dated CVC update lock - will steal it to repair earlier problem",
                serviceProvider);
      lock.setLockedAt(now);
      entityManager.merge(lock);
    }
    return lock;
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public boolean releaseCVCUpdateLock(CVCUpdateLock toRelease)
  {
    CVCUpdateLock lock = entityManager.find(CVCUpdateLock.class, toRelease.getServiceProvider());
    if (lock == null)
    {
      return false;
    }
    if (lock.getLockedAt() != toRelease.getLockedAt())
    {
      return false;
    }
    entityManager.remove(lock);
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public TerminalPermission getTerminalPermissionByMessage(String messageID)
  {
    TypedQuery<TerminalPermission> query = entityManager.createNamedQuery("getByMessageId",
                                                                          TerminalPermission.class);
    query.setParameter("pMessageID", messageID);
    try
    {
      return query.getSingleResult();
    }
    catch (NoResultException e)
    {
      return null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isOnBlackList(byte[] sectorID, byte[] specificID)
  {
    String sectorIDBase64 = DatatypeConverter.printBase64Binary(sectorID);
    String specificIDBase64 = DatatypeConverter.printBase64Binary(specificID);
    TypedQuery<Long> query = entityManager.createNamedQuery(BlackListEntry.COUNT_SPECIFICID, Long.class);
    query.setParameter(BlackListEntry.PARAM_SECTORID, sectorIDBase64);
    query.setParameter(BlackListEntry.PARAM_SPECIFICID, specificIDBase64);
    try
    {
      return !Long.valueOf(0).equals(query.getSingleResult());
    }
    catch (NoResultException e)
    {
      log.error("problem while checking blacklist entry", e);
      return true;
    }
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public void updateBlackListStoreDate(String refID, byte[] sectorID, Long blackListId)
  {
    log.debug("updateBlackListStoreDate called");
    TerminalPermission tp = entityManager.find(TerminalPermission.class, refID);
    if (sectorID != null)
    {
      tp.setSectorID(sectorID);
    }
    tp.setBlackListStoreDate(new Date());
    if (blackListId != null)
    {
      tp.setBlackListVersion(blackListId);
    }
    log.debug("Before merging BlackListStoreDate");
    entityManager.merge(tp);
    log.debug("After merging BlackListStoreDate");
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public boolean replaceBlackList(String refID, byte[] sectorID, List<byte[]> specificIDList)
  {
    TerminalPermission tp = entityManager.find(TerminalPermission.class, refID);
    String oldSectorID = null;
    boolean replaceRiKey1 = !Arrays.equals(tp.getSectorID(), sectorID);
    if (tp.getSectorID() != null)
    {
      oldSectorID = DatatypeConverter.printBase64Binary(tp.getSectorID());
    }

    Set<String> uniqueSpecificIds = getUniqueSpecificIds(specificIDList);
    String sectorIDBase64 = DatatypeConverter.printBase64Binary(sectorID);
    List<String> blackListEntries = getBlackListEntries(sectorIDBase64);
    // remove all blacklist entries in the database but not on the blacklist any more.
    removeAllNotAnyMoreUsedBlacklistEntries(sectorIDBase64, blackListEntries, uniqueSpecificIds);
    // add the new entries
    addBlackListEntries(sectorIDBase64, blackListEntries, uniqueSpecificIds);

    // if the sectorID changed remove all entries for the old sectorID
    if (replaceRiKey1 && oldSectorID != null)
    {
      removeOldSectorID(oldSectorID, sectorIDBase64);
    }
    log.debug("Finished replaceBlackList()");
    return replaceRiKey1;
  }

  private void removeOldSectorID(String oldSectorID, String sectorIDBase64)
  {
    log.debug("SectorID has changed, removing all entries with the old SectorID");
    String stringQuery = String.format("UPDATE BlackListEntry SET key.sectorID = '%s' WHERE key.sectorID = :%s",
                                       sectorIDBase64,
                                       BlackListEntry.PARAM_SECTORID);
    Query updateQuery = entityManager.createQuery(stringQuery);
    updateQuery.setParameter(BlackListEntry.PARAM_SECTORID, oldSectorID);
    updateQuery.executeUpdate();
  }

  private void removeAllNotAnyMoreUsedBlacklistEntries(String sectorID,
                                                       List<String> blackListEntries,
                                                       Set<String> uniqueSpecificIds)
  {
    List<String> tmpBlackListEntries = new LinkedList<>(blackListEntries);
    tmpBlackListEntries.removeAll(uniqueSpecificIds);

    removeSpecificIDs(sectorID, tmpBlackListEntries);
  }

  private void removeBlackListEntries(String sectorID, Set<String> uniqueSpecificIds)
  {
    removeSpecificIDs(sectorID, new LinkedList<>(uniqueSpecificIds));
  }

  private void removeSpecificIDs(String sectorID, List<String> specificIds)
  {
    log.info("{} entries that are no longer blacklisted will be removed", specificIds.size());
    for ( List<String> partition : Lists.partition(specificIds, MAX_DB_ARGS) )
    {
      Query deleteQuery = entityManager.createQuery("DELETE FROM BlackListEntry WHERE key.sectorID = :sectorID AND key.specificID in :specificIDs");
      deleteQuery.setParameter(SECTOR_ID, sectorID);
      deleteQuery.setParameter("specificIDs", partition);
      deleteQuery.executeUpdate();
    }
  }


  private List<String> getBlackListEntries(String sectorIDBase64)
  {
    TypedQuery<String> typedQuery = entityManager.createNamedQuery(BlackListEntry.SELECT_SPECIFICID_WHERE_SECTORID,
                                                                   String.class);
    typedQuery.setParameter(BlackListEntry.PARAM_SECTORID, sectorIDBase64);
    return typedQuery.getResultList();
  }

  /** {@inheritDoc} */
  @Override
  public void addBlackListEntries(byte[] sectorID, List<byte[]> specificIDList)
  {
    String sectorIDBase64 = DatatypeConverter.printBase64Binary(sectorID);
    // We have to ensure that every black listed id id just stored one time into the database.
    Set<String> uniqueSpecificIds = getUniqueSpecificIds(specificIDList);
    addBlackListEntries(sectorIDBase64, uniqueSpecificIds);
  }

  private void addBlackListEntries(String sectorIDBase64, Set<String> uniqueSpecificIds)
  {
    List<String> blackListEntries = getBlackListEntries(sectorIDBase64);
    addBlackListEntries(sectorIDBase64, blackListEntries, uniqueSpecificIds);
  }

  private void addBlackListEntries(String sectorIDBase64,
                                   List<String> blackListEntries,
                                   Set<String> inpUniqueSpecificIds)
  {
    long count = 0;
    Set<String> uniqueSpecificIds = new LinkedHashSet<>(inpUniqueSpecificIds);
    uniqueSpecificIds.removeAll(new LinkedHashSet<>(blackListEntries));
    log.info("{} new blacklist entries will be added", uniqueSpecificIds.size());

    for ( String specificIDBase64 : uniqueSpecificIds )
    {
      BlackListEntry newEntry = new BlackListEntry(new BlackListEntryPK(sectorIDBase64, specificIDBase64));
      entityManager.persist(newEntry);
      flushSessionIfNeeded(DEFAULT_BATCH_SIZE, ++count);
    }
  }

  private void flushSessionIfNeeded(int batchSize, long count)
  {
    if (count % batchSize == 0)
    {
      entityManager.flush();
      entityManager.clear();
    }
  }

  private Set<String> getUniqueSpecificIds(List<byte[]> specificIDList)
  {
    Set<String> uniqueSpecificIds = new LinkedHashSet<>(specificIDList.size());
    for ( byte[] specificID : specificIDList )
    {
      uniqueSpecificIds.add(DatatypeConverter.printBase64Binary(specificID));
    }
    return uniqueSpecificIds;
  }

  @Override
  @Transactional
  public void removeBlackListEntries(String refID, byte[] sectorID, List<byte[]> specificIDList)
  {
    String sectorIDBase64 = DatatypeConverter.printBase64Binary(sectorID);

    TerminalPermission tp = entityManager.find(TerminalPermission.class, refID);
    String oldSectorID = null;
    boolean replaceRiKey1 = !Arrays.equals(tp.getSectorID(), sectorID);
    if (tp.getSectorID() != null)
    {
      oldSectorID = DatatypeConverter.printBase64Binary(tp.getSectorID());
    }

    // if the sectorID changed change all entries for the old sectorID
    if (replaceRiKey1 && oldSectorID != null)
    {
      removeOldSectorID(oldSectorID, sectorIDBase64);
    }

    Set<String> uniqueSpecificIds = getUniqueSpecificIds(specificIDList);
    // Remove all entries still in the database
    removeBlackListEntries(sectorIDBase64, uniqueSpecificIds);
  }

  @Override
  @Transactional
  public void create(String refId)
  {
    TerminalPermission data = new TerminalPermission(refId);
    entityManager.persist(data);
  }

  @Override
  @Transactional
  public boolean remove(String refId)
  {
    TerminalPermission element = entityManager.find(TerminalPermission.class, refId);
    if (element == null)
    {
      return false;
    }
    if (element.getChain() != null)
    {
      for ( CertInChain cert : element.getChain() )
      {
        entityManager.remove(cert);
      }
    }
    if (element.getPendingCertificateRequest() != null)
    {
      entityManager.remove(element.getPendingCertificateRequest());
    }
    if (element.getSectorID() != null)
    {
      // FIXME: Use BlackListEntry.DELETE_WHERE_SECTORID
      TypedQuery<BlackListEntry> query = entityManager.createNamedQuery("getBlackListEntries",
                                                                        BlackListEntry.class);
      query.setParameter(SECTOR_ID, DatatypeConverter.printBase64Binary(element.getSectorID()));
      for ( BlackListEntry oldEntry : query.getResultList() )
      {
        entityManager.remove(oldEntry);
      }
    }
    entityManager.remove(element);
    return true;
  }

  @Override
  @Transactional
  public void storeCVCObtained(String refID, byte[] cvc, byte[][] chain, byte[] certDescription)
  {
    TerminalPermission tp = entityManager.find(TerminalPermission.class, refID);
    tp.setCvcPrivateKey(tp.getPendingCertificateRequest().getPrivateKey());
    if (certDescription == null)
    {
      if (tp.getPendingCertificateRequest().getNewCvcDescription() != null)
      {
        tp.setCvcDescription(tp.getPendingCertificateRequest().getNewCvcDescription());
      }
    }
    else
    {
      tp.setCvcDescription(certDescription);
    }
    tp.setCvc(cvc);
    try
    {
      ECCVCertificate parsed = new ECCVCertificate(cvc);
      tp.setNotOnOrAfter(parsed.getExpirationDateDate());
      // call constructor for side effect (parsing)
      new TerminalData(cvc, tp.getCvcDescription());
    }
    catch (Exception e)
    {
      log.error("{}: stored CVC data might cause problems with eCard API: {}", refID, e.getMessage());
    }
    entityManager.remove(tp.getPendingCertificateRequest());
    tp.setPendingCertificateRequest(null);
    if (chain != null)
    {
      storeCertInChain(chain, tp);
    }
  }

  @Override
  @Transactional
  public void storeCVCRequestCreated(String refID,
                                     String messageId,
                                     byte[] request,
                                     byte[] description,
                                     byte[][] chain,
                                     byte[] privKey)
  {
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    PendingCertificateRequest pending = data.getPendingCertificateRequest();
    if (pending == null)
    {
      pending = new PendingCertificateRequest(refID);
      data.setPendingCertificateRequest(pending);
      entityManager.persist(pending);
    }
    else
    {
      pending.setStatus(Status.Created);
    }
    pending.setRequestData(request);
    pending.setPrivateKey(privKey);
    pending.setMessageID(messageId);
    pending.setNewCvcDescription(description);
    if (chain != null)
    {
      storeCertInChain(chain, data);
    }
  }

  @Override
  public void storeCVCRequestSent(String refID)
  {
    TerminalPermission tp = entityManager.find(TerminalPermission.class, refID);
    tp.getPendingCertificateRequest().setStatus(PendingCertificateRequest.Status.Sent);
  }

  @Override
  @Transactional
  public void deleteCVCRequest(String refID)
  {
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    PendingCertificateRequest pending = data.getPendingCertificateRequest();
    if (pending != null)
    {
      entityManager.remove(pending);
      data.setPendingCertificateRequest(null);
    }
  }

  @Override
  @Transactional
  public void storeDefectList(String refID, byte[] defectList)
  {
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    data.setDefectList(defectList);
    data.setDefectListStoreDate(new Date());
    // removing this is only needed when old systems are migrated
    PendingCertificateRequest pendingRequest = data.getPendingCertificateRequest();
    if (data.getMasterListStoreDate() != null && pendingRequest != null
        && pendingRequest.getStatus().equals(Status.SectorKeyReceived))
    {
      entityManager.remove(pendingRequest);
      data.setPendingCertificateRequest(null);
    }
  }

  @Override
  public void storeMasterList(String refID, byte[] masterList)
  {
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    data.setMasterList(masterList);
    data.setMasterListStoreDate(new Date());
  }

  @Override
  @Transactional
  public void storePublicSectorKey(String refID, byte[] publicSectorKey)
  {
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    data.setRiKey1(publicSectorKey);
    // removing this is only needed when old systems are migrated
    PendingCertificateRequest pendingRequest = data.getPendingCertificateRequest();
    if (pendingRequest != null
        && PendingCertificateRequest.Status.CertReceived.equals(pendingRequest.getStatus()))
    {
      entityManager.remove(pendingRequest);
      data.setPendingCertificateRequest(null);
    }
  }

  @Override
  public void storeCVCObtainedError(String refID, String additionalInfo)
  {
    TerminalPermission data = entityManager.find(TerminalPermission.class, refID);
    data.getPendingCertificateRequest().setStatus(Status.Failure);
    data.getPendingCertificateRequest().setAdditionalInfo(additionalInfo);
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public ChangeKeyLock obtainChangeKeyLock(String keyName, int type)
  {
    long now = System.currentTimeMillis();
    String myAddress = null;
    try
    {
      myAddress = InetAddress.getLocalHost().toString();
    }
    catch (UnknownHostException e)
    {
      // unable to identify myself, locking not possible
      return null;
    }

    ChangeKeyLock lock = this.entityManager.find(ChangeKeyLock.class, keyName);
    if (lock == null)
    {
      lock = new ChangeKeyLock(keyName, myAddress, now, type);
      this.entityManager.persist(lock);
    }
    else
    {
      // it is already my own
      if (myAddress.equals(lock.getAutentIP()) && type == lock.getType())
      {
        // just update time
        lock.setLockedAt(now);
        entityManager.merge(lock);
        return lock;
      }
      // only same type lock can be stolen
      // accepted maximum for a single key distribution: ten minutes
      if (lock.getType() != type || lock.getLockedAt() > now - 1000L * 60 * 10)
      {
        return null;
      }
      log.error("Found out-dated key update lock - will steal it to repair earlier problem for: {}", keyName);
      lock.setLockedAt(now);
      lock.setAutentIP(myAddress);
      entityManager.merge(lock);
    }
    return lock;
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public boolean releaseChangeKeyLock(ChangeKeyLock toRelease)
  {
    ChangeKeyLock lock = this.entityManager.find(ChangeKeyLock.class, toRelease.getKeyName());
    if (lock == null)
    {
      return false;
    }
    this.entityManager.remove(lock);
    return true;
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public boolean releaseChangeKeyLockOwner(ChangeKeyLock toRelease)
  {
    ChangeKeyLock lock = this.entityManager.find(ChangeKeyLock.class, toRelease.getKeyName());
    if (lock == null)
    {
      return false;
    }
    lock.setAutentIP("VOID");
    this.entityManager.merge(lock);
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public List<ChangeKeyLock> getAllChangeKeyLocksByInstance(boolean own)
  {
    List<ChangeKeyLock> resultList = new ArrayList<>();
    try
    {
      String myAddress = InetAddress.getLocalHost().toString();
      String ownChoice = own ? "=" : "<>";
      String stringQuery = String.format("SELECT l FROM ChangeKeyLock l WHERE l.autentIP %s'%s'",
                                         ownChoice,
                                         myAddress);
      TypedQuery<ChangeKeyLock> query = this.entityManager.createQuery(stringQuery, ChangeKeyLock.class);
      for ( ChangeKeyLock q : query.getResultList() )
      {
        resultList.add(q);
      }
    }
    catch (UnknownHostException e)
    {
      // nothing to do
    }
    return resultList;
  }

  /** {@inheritDoc} */
  @Override
  public boolean changeKeyLockExists(String keyName)
  {
    AssertUtil.notNull(keyName, "key alias");
    ChangeKeyLock lock = this.entityManager.find(ChangeKeyLock.class, keyName);
    return lock != null && lock.getType() == ChangeKeyLock.TYPE_DISTRIBUTE;
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public boolean iHaveLock(String keyAlias)
  {
    if (keyAlias == null)
    {
      log.debug("unable to detect lock for null alias");
      return false;
    }
    try
    {
      String myAddress = InetAddress.getLocalHost().toString();
      ChangeKeyLock lock = this.entityManager.find(ChangeKeyLock.class, keyAlias);
      if (lock != null && myAddress.equals(lock.getAutentIP()))
      {
        lock.setLockedAt(System.currentTimeMillis());
        entityManager.merge(lock);
        return true;
      }
    }
    catch (UnknownHostException e)
    {
      // false anyway
    }
    return false;
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public void archiveCVC(String alias, byte[] cvcData)
  {
    if (alias == null || alias.length() == 0)
    {
      log.debug("unable to archive CVC without alias");
      return;
    }
    if (cvcData == null || cvcData.length == 0)
    {
      log.debug("unable to archive CVC without data");
      return;
    }

    KeyArchive ka = this.entityManager.find(KeyArchive.class, alias);
    if (ka == null)
    {
      ka = new KeyArchive(alias, cvcData);
      this.entityManager.persist(ka);
    }
    else
    {
      ka.setCvc(cvcData);
      this.entityManager.merge(ka);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Transactional
  public void archiveKey(String alias, byte[] keyData)
  {
    if (alias == null || alias.length() == 0)
    {
      log.debug("unable to archive key without alias");
      return;
    }
    if (keyData == null || keyData.length == 0)
    {
      log.debug("unable to archive key without data");
      return;
    }

    KeyArchive ka = this.entityManager.find(KeyArchive.class, alias);
    if (ka == null)
    {
      ka = new KeyArchive(alias);
      ka.setPrivateKey(keyData);
      this.entityManager.persist(ka);
    }
    else
    {
      ka.setPrivateKey(keyData);
      this.entityManager.merge(ka);
    }
  }

  @Override
  public Long getNumberBlacklistEntries(byte[] sectorID)
  {
    String sectorIDBase64 = DatatypeConverter.printBase64Binary(sectorID);
    TypedQuery<Long> query = entityManager.createNamedQuery(BlackListEntry.COUNT_SPECIFICID_WHERE_SECTORID,
                                                            Long.class);
    query.setParameter(BlackListEntry.PARAM_SECTORID, sectorIDBase64);
    try
    {
      return query.getSingleResult();
    }
    catch (NoResultException e)
    {
      log.error("problem while checking blacklist entry", e);
      return Long.valueOf(0);
    }
  }

  @Override
  public List<String> getTerminalPermissionRefIDList()
  {
    TypedQuery<TerminalPermission> query = entityManager.createNamedQuery("getTerminalPermissionList",
                                                                          TerminalPermission.class);
    List<String> entityIDList = new ArrayList<>();
    for ( TerminalPermission tp : query.getResultList() )
    {
      entityIDList.add(tp.getRefID());
    }
    return entityIDList;
  }

  /** {@inheritDoc} */
  @Override
  public ApplicationContext getApplicationContext()
  {
    return applicationContext;
  }
}
