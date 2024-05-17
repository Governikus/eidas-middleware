/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.config.model.ServiceProviderDetails;
import de.governikus.eumw.poseidas.eidmodel.TerminalData;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListStorageException;
import de.governikus.eumw.poseidas.server.pki.entities.CVCUpdateLock;
import de.governikus.eumw.poseidas.server.pki.entities.CertInChain;
import de.governikus.eumw.poseidas.server.pki.entities.CertInChainPK;
import de.governikus.eumw.poseidas.server.pki.entities.ChangeKeyLock;
import de.governikus.eumw.poseidas.server.pki.entities.KeyArchive;
import de.governikus.eumw.poseidas.server.pki.entities.PendingCertificateRequest;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.repositories.CVCUpdateLockRepository;
import de.governikus.eumw.poseidas.server.pki.repositories.CertInChainRepository;
import de.governikus.eumw.poseidas.server.pki.repositories.ChangeKeyLockRepository;
import de.governikus.eumw.poseidas.server.pki.repositories.KeyArchiveRepository;
import de.governikus.eumw.poseidas.server.pki.repositories.PendingCertificateRequestRepository;
import de.governikus.eumw.poseidas.server.pki.repositories.RequestSignerCertificateRepository;
import de.governikus.eumw.poseidas.server.pki.repositories.TerminalPermissionRepository;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Access to terminal permission data. Use de.bos_bremen.gov2.jca_provider.ocf.asn1.cvc.CertificateRequestGenerator for
 * getting the data!
 *
 * @author tt
 */
@Repository
@Transactional
@Slf4j
@RequiredArgsConstructor
public class TerminalPermissionAOBean implements TerminalPermissionAO
{

  private static final String TERMINAL_PERMISSION_FOR_NOT_FOUND = "TerminalPermission for {} not found";

  private final TerminalPermissionRepository terminalPermissionRepository;

  private final RequestSignerCertificateRepository requestSignerCertificateRepository;

  private final CertInChainRepository certInChainRepository;

  private final CVCUpdateLockRepository cvcUpdateLockRepository;

  private final BlockListService blockListService;

  private final PendingCertificateRequestRepository pendingCertificateRequestRepository;

  private final ChangeKeyLockRepository changeKeyLockRepository;

  private final KeyArchiveRepository keyArchiveRepository;

  private final ConfigurationService configurationService;

  /**
   * {@inheritDoc}
   */
  @Override
  public void storeCertInChain(String refID, byte[][] chain)
  {
    TerminalPermission data = terminalPermissionRepository.findById(refID).orElse(null);
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
        certInChainRepository.save(entry);
      }
      else
      {
        oldEntry.setData(entry.getData());
        certInChainRepository.save(entry);
        oldChain.remove(oldEntry.getKey());
      }
    }
    for ( CertInChain entry : oldChain.values() )
    {
      data.getChain().remove(entry);
      certInChainRepository.delete(entry);
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public TerminalPermission getTerminalPermission(String refID)
  {
    return terminalPermissionRepository.findById(refID).orElse(null);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Map<String, Date> getExpirationDates()
  {
    Map<String, Date> result = new HashMap<>();
    List<TerminalPermission> tpList = terminalPermissionRepository.findAll(Sort.by(Sort.Direction.ASC, "notOnOrAfter"));
    for ( TerminalPermission permission : tpList )
    {
      if (permission.getNotOnOrAfter() != null)
      {
        result.put(permission.getRefID(), permission.getNotOnOrAfter());
      }
    }
    return result;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  @Transactional
  public CVCUpdateLock obtainCVCUpdateLock(String serviceProvider)
  {
    long now = System.currentTimeMillis();

    Optional<CVCUpdateLock> lockOptional = cvcUpdateLockRepository.findById(serviceProvider);
    CVCUpdateLock lock;
    if (lockOptional.isPresent())
    {
      lock = lockOptional.get();
      // accepted maximum for a single CVC update: ten minutes
      if (lock.getLockedAt() > now - 1000L * 60 * 10)
      {
        return null;
      }
      log.error("{}: Found out-dated CVC update lock - will steal it to repair earlier problem", serviceProvider);
      lock.setLockedAt(now);
      cvcUpdateLockRepository.save(lock);
    }
    else
    {
      lock = new CVCUpdateLock(serviceProvider, now);
      cvcUpdateLockRepository.save(lock);
    }
    return lock;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  @Transactional
  public boolean releaseCVCUpdateLock(CVCUpdateLock toRelease)
  {
    if (toRelease == null)
    {
      throw new IllegalArgumentException("Lock to be released cannot be null");
    }
    Optional<CVCUpdateLock> lockOptional = cvcUpdateLockRepository.findById(toRelease.getServiceProvider());
    CVCUpdateLock lock;
    if (lockOptional.isPresent())
    {
      lock = lockOptional.get();
    }
    else
    {
      return false;
    }
    if (lock.getLockedAt() != toRelease.getLockedAt())
    {
      return false;
    }
    cvcUpdateLockRepository.delete(lock);
    return true;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public TerminalPermission getTerminalPermissionByMessage(String messageID)
  {
    Optional<TerminalPermission> terminalPermission = terminalPermissionRepository.findByPendingRequest_MessageID(messageID);
    return terminalPermission.orElse(null);
  }


  @Override
  @Transactional
  public void create(String refId)
  {
    TerminalPermission data = new TerminalPermission(refId);
    terminalPermissionRepository.save(data);
  }

  @Override
  @Transactional
  public boolean remove(String refId)
  {
    Optional<TerminalPermission> terminalPermissionOptional = terminalPermissionRepository.findById(refId);

    if (!terminalPermissionOptional.isPresent())
    {
      return false;
    }

    TerminalPermission terminalPermission = terminalPermissionOptional.get();

    if (terminalPermission.getChain() != null)
    {
      for ( CertInChain cert : terminalPermission.getChain() )
      {
        certInChainRepository.delete(cert);
      }
    }
    if (terminalPermission.getPendingRequest() != null)
    {
      pendingCertificateRequestRepository.delete(terminalPermission.getPendingRequest());
    }
    if (terminalPermission.getSectorID() != null)
    {
      try
      {
        blockListService.removeBlockList(terminalPermission);
      }
      catch (BlockListStorageException e)
      {
        log.warn("Error while deleting Block List file for terminal permission {}", refId, e);
      }
    }
    terminalPermissionRepository.delete(terminalPermission);
    return true;
  }

  @Override
  @Transactional
  public void storeCVCObtained(String refID, byte[] cvc, byte[][] chain, byte[] certDescription)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (!tpOptional.isPresent())
    {
      log.warn(TERMINAL_PERMISSION_FOR_NOT_FOUND, refID);
      return;
    }

    TerminalPermission tp = tpOptional.get();
    tp.setCvcPrivateKey(tp.getPendingRequest().getPrivateKey());
    if (certDescription == null)
    {
      if (tp.getPendingRequest().getNewCvcDescription() != null)
      {
        tp.setCvcDescription(tp.getPendingRequest().getNewCvcDescription());
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
    pendingCertificateRequestRepository.delete(tp.getPendingRequest());
    tp.setPendingRequest(null);
    if (chain != null)
    {
      storeCertInChain(chain, tp);
    }
  }

  @Override
  public void storeCVCRequestCreated(String refID,
                                     String messageId,
                                     byte[] request,
                                     byte[] description,
                                     byte[][] chain,
                                     byte[] privKey)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (!tpOptional.isPresent())
    {
      log.warn(TERMINAL_PERMISSION_FOR_NOT_FOUND, refID);
      return;
    }

    TerminalPermission tp = tpOptional.get();
    PendingCertificateRequest pending = tp.getPendingRequest();
    if (pending == null)
    {
      pending = new PendingCertificateRequest(refID);
    }
    else
    {
      pending.setStatus(PendingCertificateRequest.Status.CREATED);
    }
    pending.setRequestData(request);
    pending.setPrivateKey(privKey);
    pending.setMessageID(messageId);
    pending.setNewCvcDescription(description);
    if (chain != null)
    {
      storeCertInChain(chain, tp);
    }

    PendingCertificateRequest savedPendingCertificateRequest = pendingCertificateRequestRepository.saveAndFlush(pending);

    tp.setPendingRequest(savedPendingCertificateRequest);
    Integer usedSequenceNumber = ServiceProviderDetails.getNumberOfCHR(CVCRequestHandler.getHolderReferenceStringOfPendingRequest(savedPendingCertificateRequest));
    if (usedSequenceNumber != null)
    {
      tp.setNextCvcSequenceNumber(usedSequenceNumber);
    }

    terminalPermissionRepository.saveAndFlush(tp);
  }

  @Override
  public void storeCVCRequestSent(String refID)
  {
    TerminalPermission tp = terminalPermissionRepository.findById(refID).orElse(null);
    if (tp == null)
    {
      log.error("Could not find refID: {}", refID);
      return;
    }
    tp.getPendingRequest().setStatus(PendingCertificateRequest.Status.SENT);
    terminalPermissionRepository.saveAndFlush(tp);
  }

  @Override
  @Transactional
  public void deleteCVCRequest(String refID)
  {
    TerminalPermission tp = terminalPermissionRepository.findById(refID).orElse(null);
    if (tp == null)
    {
      log.error("Could not find refID: {}", refID);
      return;
    }
    PendingCertificateRequest pending = tp.getPendingRequest();
    if (pending == null)
    {
      return;
    }
    pendingCertificateRequestRepository.delete(pending);
    tp.setPendingRequest(null);
    terminalPermissionRepository.saveAndFlush(tp);
  }

  @Override
  @Transactional
  public void storeDefectList(String refID, byte[] defectList)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (!tpOptional.isPresent())
    {
      log.warn(TERMINAL_PERMISSION_FOR_NOT_FOUND, refID);
      return;
    }

    TerminalPermission tp = tpOptional.get();
    tp.setDefectList(defectList);
    tp.setDefectListStoreDate(new Date());
  }

  @Override
  public void storeMasterList(String refID, byte[] masterList)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (!tpOptional.isPresent())
    {
      log.warn(TERMINAL_PERMISSION_FOR_NOT_FOUND, refID);
      return;
    }

    TerminalPermission tp = tpOptional.get();
    tp.setMasterList(masterList);
    tp.setMasterListStoreDate(new Date());
  }

  @Override
  @Transactional
  public void storePublicSectorKey(String refID, byte[] publicSectorKey)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (!tpOptional.isPresent())
    {
      log.warn(TERMINAL_PERMISSION_FOR_NOT_FOUND, refID);
      return;
    }

    TerminalPermission tp = tpOptional.get();
    tp.setRiKey1(publicSectorKey);
  }

  @Override
  public void storeCVCObtainedError(String refID, String additionalInfo)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (!tpOptional.isPresent())
    {
      log.warn(TERMINAL_PERMISSION_FOR_NOT_FOUND, refID);
      return;
    }

    TerminalPermission tp = tpOptional.get();
    tp.getPendingRequest().setStatus(PendingCertificateRequest.Status.FAILURE);
    tp.getPendingRequest().setAdditionalInfo(additionalInfo);
  }

  /**
   * {@inheritDoc}
   */
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

    Optional<ChangeKeyLock> lockOptional = changeKeyLockRepository.findById(keyName);

    ChangeKeyLock lock;
    if (lockOptional.isPresent())
    {
      lock = lockOptional.get();
      // it is already my own
      if (myAddress.equals(lock.getAutentIP()) && type == lock.getType())
      {
        // just update time
        lock.setLockedAt(now);
        changeKeyLockRepository.save(lock);
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
    }
    else
    {
      lock = new ChangeKeyLock(keyName, myAddress, now, type);
    }
    changeKeyLockRepository.save(lock);
    return lock;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  @Transactional
  public boolean releaseChangeKeyLock(ChangeKeyLock toRelease)
  {
    Optional<ChangeKeyLock> lockOptional = changeKeyLockRepository.findById(toRelease.getKeyName());
    if (!lockOptional.isPresent())
    {
      return false;
    }
    changeKeyLockRepository.delete(lockOptional.get());
    return true;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  @Transactional
  public boolean releaseChangeKeyLockOwner(ChangeKeyLock toRelease)
  {
    Optional<ChangeKeyLock> lockOptional = changeKeyLockRepository.findById(toRelease.getKeyName());
    if (!lockOptional.isPresent())
    {
      return false;
    }
    ChangeKeyLock lock = lockOptional.get();

    lock.setAutentIP("VOID");
    changeKeyLockRepository.save(lock);
    return true;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public List<ChangeKeyLock> getAllChangeKeyLocksByInstance(boolean own)
  {
    String myAddress = null;
    try
    {
      myAddress = InetAddress.getLocalHost().toString();
    }
    catch (UnknownHostException e)
    {
      return new ArrayList<>();
    }

    return own ? changeKeyLockRepository.getAllByAutentIP(myAddress)
      : changeKeyLockRepository.getAllByAutentIPNot(myAddress);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean changeKeyLockExists(String keyName)
  {
    AssertUtil.notNull(keyName, "key alias");
    Optional<ChangeKeyLock> lockOptional = changeKeyLockRepository.findById(keyName);

    return lockOptional.isPresent() && lockOptional.get().getType() == ChangeKeyLock.TYPE_DISTRIBUTE;
  }

  /**
   * {@inheritDoc}
   */
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
      Optional<ChangeKeyLock> lockOptional = changeKeyLockRepository.findById(keyAlias);
      if (lockOptional.isPresent() && myAddress.equals(lockOptional.get().getAutentIP()))
      {
        ChangeKeyLock lock = lockOptional.get();
        lock.setLockedAt(System.currentTimeMillis());
        changeKeyLockRepository.save(lock);
        return true;
      }
    }
    catch (UnknownHostException e)
    {
      // false anyway
    }
    return false;
  }

  /**
   * {@inheritDoc}
   */
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

    KeyArchive ka = keyArchiveRepository.findById(alias).orElse(new KeyArchive(alias, cvcData));
    ka.setCvc(cvcData);
    keyArchiveRepository.save(ka);
  }

  /**
   * {@inheritDoc}
   */
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

    Optional<KeyArchive> kaOptional = keyArchiveRepository.findById(alias);
    KeyArchive ka;
    if (kaOptional.isPresent())
    {
      ka = kaOptional.get();
    }
    else
    {
      ka = new KeyArchive(alias);
    }
    ka.setPrivateKey(keyData);
    keyArchiveRepository.save(ka);
  }

  @Override
  public List<String> getTerminalPermissionRefIDList()
  {
    return terminalPermissionRepository.findAll(Sort.by(Sort.Direction.ASC, "notOnOrAfter"))
                                       .stream()
                                       .map(term -> term.getRefID())
                                       .collect(Collectors.toList());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Integer getCurrentRscChrId(String refID)
  {
    return getRscChrId(refID, true);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Integer getPendingRscChrId(String refID)
  {
    return getRscChrId(refID, false);
  }

  private Integer getRscChrId(String refID, boolean current)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (!tpOptional.isPresent())
    {
      log.error("RefID does not exist");
      return null;
    }
    RequestSignerCertificate rsc = current ? tpOptional.get().getCurrentRequestSignerCertificate()
      : tpOptional.get().getPendingRequestSignerCertificate();
    if (rsc == null)
    {
      return null;
    }
    return rsc.getKey().getPosInChain();
  }

  public RequestSignerCertificate.Status getPendingRscStatus(String refID)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (tpOptional.isEmpty())
    {
      log.error("RefID does not exist");
      return null;
    }
    RequestSignerCertificate rsc = tpOptional.get().getPendingRequestSignerCertificate();
    if (rsc == null)
    {
      return null;
    }
    return rsc.getStatus();
  }

  public void setPendingRscStatusFailed(String refID)
  {
    Optional<TerminalPermission> tpOptional = terminalPermissionRepository.findById(refID);
    if (tpOptional.isEmpty())
    {
      log.error("RefID does not exist");
      return;
    }
    RequestSignerCertificate rsc = tpOptional.get().getPendingRequestSignerCertificate();
    if (rsc == null)
    {
      return;
    }
    rsc.setStatus(RequestSignerCertificate.Status.FAILURE);
    requestSignerCertificateRepository.saveAndFlush(rsc);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  @Transactional
  public void makePendingRscToCurrentRsc(String refID, boolean deletePendingCertificateRequest)
  {
    Optional<TerminalPermission> terminalPermissionOptional = terminalPermissionRepository.findById(refID);
    if (!terminalPermissionOptional.isPresent())
    {
      log.error("{}: Could not set current request signer certificate. RefID does not exist.", refID);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.RSC_TRAP_CHANGE_TO_CURRENT_RSC, SNMPConstants.RSC_NO_REFID);
      return;
    }

    TerminalPermission terminalPermission = terminalPermissionOptional.get();

    if (terminalPermission.getPendingRequestSignerCertificate() == null)
    {
      log.error("{}: Could not change pending request signer certificate to current, because there is no pending one!",
                refID);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.RSC_TRAP_CHANGE_TO_CURRENT_RSC, SNMPConstants.RSC_NO_PENDING);
      return;
    }

    if (terminalPermission.getCurrentRequestSignerCertificate() != null)
    {
      requestSignerCertificateRepository.delete(terminalPermission.getCurrentRequestSignerCertificate());
    }

    terminalPermission.setCurrentRequestSignerCertificate(terminalPermission.getPendingRequestSignerCertificate());
    terminalPermission.setPendingRequestSignerCertificate(null);
    // if there is a pending CVC request (signed by old RSC), the DVCA will no longer accept it, so it must be created
    // again with new sequence number and signed by new RSC
    if (terminalPermission.getPendingRequest() != null && deletePendingCertificateRequest)
    {
      terminalPermission.increaseSequenceNumber();
      terminalPermission.setPendingRequest(null);
    }
    terminalPermission.setAutomaticRscRenewFailed(null);

    terminalPermissionRepository.saveAndFlush(terminalPermission);
    log.info("{}: Successfully set current request signer certificate", refID);
    SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.RSC_TRAP_CHANGE_TO_CURRENT_RSC, SNMPConstants.RSC_SET_CURRENT);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  @Transactional
  public void setPendingRequestSignerCertificate(String refID, RequestSignerCertificate pendingRequestSignerCertificate)
    throws TerminalPermissionNotFoundException
  {
    Optional<TerminalPermission> terminalPermissionOptional = terminalPermissionRepository.findById(refID);
    if (terminalPermissionOptional.isEmpty())
    {
      log.error("Could not set pending RSC for {}. RefID does not exist.", refID);
      throw new TerminalPermissionNotFoundException();
    }

    TerminalPermission terminalPermission = terminalPermissionOptional.get();
    RequestSignerCertificate oldRequestSignerCertificate = terminalPermission.getPendingRequestSignerCertificate();
    terminalPermission.setPendingRequestSignerCertificate(pendingRequestSignerCertificate);
    terminalPermission.setAutomaticRscRenewFailed(null);
    if (oldRequestSignerCertificate != null)
    {
      requestSignerCertificateRepository.delete(oldRequestSignerCertificate);
    }
    if (pendingRequestSignerCertificate != null)
    {
      requestSignerCertificateRepository.save(pendingRequestSignerCertificate);
    }
    terminalPermissionRepository.saveAndFlush(terminalPermission);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void deletePendingRequestSignerCertificate(String refID) throws TerminalPermissionNotFoundException
  {
    setPendingRequestSignerCertificate(refID, null);
  }

  @Override
  public void setAutomaticCvcRenewFailed(String refID, boolean isCvcRenewalFailed)
  {
    Optional<TerminalPermission> terminalPermissionOptional = terminalPermissionRepository.findById(refID);
    if (terminalPermissionOptional.isEmpty())
    {
      log.error("Could not set automatic cvc renewal failed for {}. RefID does not exist.", refID);
      return;
    }
    TerminalPermission terminalPermission = terminalPermissionOptional.get();
    terminalPermission.setAutomaticCvcRenewFailed(isCvcRenewalFailed);
    terminalPermissionRepository.saveAndFlush(terminalPermission);
  }

  @Override
  public X509Certificate getRequestSignerCertificate(String refID, boolean current)
  {
    byte[] certByteArray = null;
    RequestSignerCertificate rsc = getRscInternal(refID, current);
    if (rsc != null)
    {
      certByteArray = rsc.getX509RequestSignerCertificate();
    }
    if (ArrayUtil.isNullOrEmpty(certByteArray))
    {
      if (current)
      {
        log.debug("No request signer certificate for refId {} found", refID);
      }
      else
      {
        log.debug("No pending request signer certificate for refId {} found", refID);
      }
      return null;
    }
    try
    {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X509",
                                                                             SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      return (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certByteArray));
    }
    catch (CertificateException e)
    {
      log.error("Can not create certificate factory", e);
    }
    return null;
  }

  @Override
  public byte[] getRequestSignerKey(String refID, boolean current)
  {
    RequestSignerCertificate rsc = getRscInternal(refID, current);
    if (rsc != null)
    {
      return rsc.getPrivateKey();
    }
    if (current)
    {
      log.debug("No request signer certificate for refID {} found", refID);
    }
    else
    {
      log.debug("No pending request signer certificate for refID {} found", refID);
    }
    return null;
  }

  private RequestSignerCertificate getRscInternal(String refID, boolean current)
  {
    Optional<TerminalPermission> tp = terminalPermissionRepository.findById(refID);
    if (tp.isPresent())
    {
      TerminalPermission terminalPermission = tp.get();
      return current ? terminalPermission.getCurrentRequestSignerCertificate()
        : terminalPermission.getPendingRequestSignerCertificate();
    }
    log.error("No terminal permission for refID {} found", refID);
    return null;
  }

  @Override
  public String getRequestSignerCertificateHolder(String refID)
  {
    Optional<TerminalPermission> tp = terminalPermissionRepository.findById(refID);
    if (tp.isPresent())
    {
      return tp.get().getRscChr();
    }
    log.error("No terminal permission for refID {} found", refID);
    return null;
  }

  @Override
  public boolean isPublicClient(String entityId)
  {
    var optionalPublicServiceProviderName = configurationService.getConfiguration()
                                                                .map(EidasMiddlewareConfig::getEidasConfiguration)
                                                                .map(EidasMiddlewareConfig.EidasConfiguration::getPublicServiceProviderName);
    if (optionalPublicServiceProviderName.isEmpty())
    {
      return false;
    }
    final String publicSpName = optionalPublicServiceProviderName.get();
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidConfiguration)
                               .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                               .stream()
                               .flatMap(List::stream)
                               .anyMatch(sp -> sp.getCVCRefID().equals(entityId) && sp.getName().equals(publicSpName));
  }

  @Override
  public void setRequestSignerCertificateHolder(String refID, String holder) throws TerminalPermissionNotFoundException
  {
    Optional<TerminalPermission> tp = terminalPermissionRepository.findById(refID);
    if (!tp.isPresent())
    {
      log.error("Could not set RSC holder for {}. RefID does not exist.", refID);
      throw new TerminalPermissionNotFoundException();
    }
    TerminalPermission permission = tp.get();
    permission.setRscChr(holder);
    terminalPermissionRepository.saveAndFlush(permission);
  }

  @Override
  public void increaseSequenceNumber(String refId)
  {
    Optional<TerminalPermission> tp = terminalPermissionRepository.findById(refId);
    if (!tp.isPresent())
    {
      log.error("Could not increase sequence number for {}. RefID does not exist.", refId);
      return;
    }
    TerminalPermission permission = tp.get();
    permission.increaseSequenceNumber();
    terminalPermissionRepository.saveAndFlush(permission);
  }

  @Override
  public void setAutomaticRscRenewFailed(String refID, String cause)
  {
    Optional<TerminalPermission> terminalPermissionOptional = terminalPermissionRepository.findById(refID);
    if (terminalPermissionOptional.isEmpty())
    {
      log.error("Could not set automatic RSC renewal failed for {}. RefID does not exist.", refID);
      return;
    }
    TerminalPermission terminalPermission = terminalPermissionOptional.get();
    terminalPermission.setAutomaticRscRenewFailed(cause);
    terminalPermissionRepository.saveAndFlush(terminalPermission);
  }

  @Override
  public String getAutomaticRscRenewFailed(String refID)
  {
    Optional<TerminalPermission> terminalPermissionOptional = terminalPermissionRepository.findById(refID);
    if (terminalPermissionOptional.isEmpty())
    {
      log.error("Could not get automatic RSC renewal failed for {}. RefID does not exist.", refID);
      return null;
    }
    TerminalPermission terminalPermission = terminalPermissionOptional.get();
    return terminalPermission.getAutomaticRscRenewFailed();
  }
}
