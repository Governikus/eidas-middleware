/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.cms.CMSException;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardbase.crypto.DigestUtil;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.BlackList;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.BlackListDetails;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListConsistencyException;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListStorageException;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.DvcaServiceFactory;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdService.BlackListResult;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdService110;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdService140;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * Process of requesting public sector key and block list
 *
 * @author tautenhahn, hme
 */
@Slf4j
public class RestrictedIdHandler extends BerCaRequestHandlerBase
{

  private static final String UNABLE_TO_PARSE_GIVEN_CVC = "unable to parse given cvc";

  private final BlockListService blockListService;

  /**
   * Create instance for one-time use. May be re-used only for same configuration version.
   *
   * @param nPaConf
   * @param facade
   * @param configurationService
   */
  RestrictedIdHandler(ServiceProviderType nPaConf,
                      TerminalPermissionAO facade,
                      KeyStore hsmKeyStore,
                      ConfigurationService configurationService,
                      DvcaServiceFactory dvcaServiceFactory,
                      BlockListService blockListService)
    throws GovManagementException
  {
    super(nPaConf, facade, hsmKeyStore, configurationService, dvcaServiceFactory);
    this.blockListService = blockListService;
  }


  private byte[] getSectorID(TerminalPermission data) throws GovManagementException
  {
    if (data == null || data.getCvc() == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("no terminal permission for entry "
                                                                                               + cvcRefId));
    }
    try
    {
      ECCVCertificate cvc = new ECCVCertificate(data.getCvc());
      if (cvc.getSectorPublicKeyHash() == null)
      {
        throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("no sector public key hash in the block list or cvc found for entry "
                                                                                                 + cvcRefId));
      }
      return cvc.getSectorPublicKeyHash();
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException(UNABLE_TO_PARSE_GIVEN_CVC, e);
    }
  }

  void requestPublicSectorKeyIfNeeded() throws GovManagementException
  {
    TerminalPermission data = facade.getTerminalPermission(cvcRefId);
    if (data.getRiKey1() == null)
    {
      log.info("{}: no public sector key found, will fetch one now", cvcRefId);
      requestPublicSectorKey();
      log.info("{}: missing public sector key has been obtained and stored", cvcRefId);
    }
    else
    {
      try
      {
        MessageDigest digest = getMessageDigestForTerminal(data);
        byte[] hash = digest.digest(data.getRiKey1());
        byte[] sectorId = getSectorID(data);

        if (hash == null || !Arrays.equals(sectorId, hash))
        {
          log.info("{}: public sector key has changed, will fetch new one now", cvcRefId);
          requestPublicSectorKey();
          log.info("{}: new public sector key was fetched", cvcRefId);
        }
      }
      catch (NoSuchAlgorithmException e)
      {
        throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("SHA-256 not supported "
                                                                                                 + cvcRefId));
      }
    }
  }

  /**
   * Get the digest algorithm from the public key of the CVC
   *
   * @param data The terminal whose digest algorithm should be returned
   * @return The digest algorithm that was used in the public key of the CVC or SHA-256 if the public key digest
   *         algorithm could not be determined
   * @throws NoSuchAlgorithmException
   */
  private MessageDigest getMessageDigestForTerminal(TerminalPermission data) throws NoSuchAlgorithmException
  {
    MessageDigest digest;
    try
    {
      OID oid = data.getFullCvc().getPublicKey().getOID();
      digest = DigestUtil.getDigestByOID(oid);
    }
    catch (IOException | IllegalArgumentException | NoSuchAlgorithmException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to generate digest for {}", data, e);
      }
      // fallback, not guaranteed to work (SHA-256 is currently the only algorithm employed, subject to
      // change)
      digest = MessageDigest.getInstance("SHA-256");
    }
    return digest;
  }

  /**
   * Request a public sector key and store it in the database.
   *
   * @throws GovManagementException
   */
  private void requestPublicSectorKey() throws GovManagementException
  {
    TerminalPermission data = facade.getTerminalPermission(cvcRefId);
    byte[] sectorId = getSectorID(data);
    byte[] sectorPK;
    try
    {
      PKIServiceConnector.getContextLock();
      log.debug("{}: obtained lock on SSL context for downloading public sector key", cvcRefId);
      RestrictedIdService wrapper = dvcaServiceFactory.createRestrictedIdService(serviceProvider, hsmKeyStore);
      sectorPK = wrapper.getSectorPublicKey(sectorId);
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
    }
    facade.storePublicSectorKey(cvcRefId, sectorPK);
  }

  /**
   * request a block list and store it in the database
   *
   * @param all <code>true</code> to store the block list for all service providers contained, <code>false</code> to
   *          store only the one for the provider referred by the entityID of this instance
   * @return The sectors the block list was renewed for.
   * @throws GovManagementException
   */
  Set<ByteBuffer> requestBlackList(boolean all, boolean delta) throws GovManagementException
  {
    log.info("{}: started requestBlackList. All: {} | Delta: {}", cvcRefId, all, delta);
    long blackListStart;
    BlackListResult blResult;
    try
    {
      PKIServiceConnector.getContextLock();
      log.debug("{}: obtained lock on SSL context for downloading block list", cvcRefId);
      TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
      RestrictedIdService wrapper = dvcaServiceFactory.createRestrictedIdService(serviceProvider, hsmKeyStore);

      blackListStart = System.currentTimeMillis();
      byte[] deltaID = null;
      if (delta)
      {
        log.debug("{}: trying to request delta block list", cvcRefId);

        deltaID = tp.getBlackListVersion() == null ? null : BigInteger.valueOf(tp.getBlackListVersion()).toByteArray();
      }

      byte[] sectorID = tp.getSectorID();
      if (ArrayUtils.isEmpty(sectorID))
      {
        sectorID = getSectorID(tp);
      }
      blResult = wrapper.getBlacklistResult(deltaID, sectorID);
    }
    catch (GovManagementException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to request block list", e);
      }
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw e;
    }
    catch (Exception e)
    {
      log.error("{}: cannot download block list", cvcRefId, e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE,
                                       dvcaConfiguration.getRestrictedIdServiceUrl(), e.getLocalizedMessage());
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
      log.debug("{}: block list request done", cvcRefId);
    }
    if (blResult == null || (blResult.getUri() == null && blResult.getDeltaAdded() == null))
    {
      log.info("{}: Did not receive a block list from BerCa", cvcRefId);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      return new HashSet<>();
    }
    if (RestrictedIdService140.NO_NEW_DATA.equals(blResult) || RestrictedIdService110.NO_NEW_DATA.equals(blResult))
    {
      log.info("{}: No newer delta block list from BerCa available", cvcRefId);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_RENEWED);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                  System.currentTimeMillis() - blackListStart);
      return new HashSet<>();
    }

    // No URI means we received a delta list
    if (blResult.getUri() == null)
    {
      try
      {
        Set<ByteBuffer> result = processDeltaBlackList(all, blResult);
        SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                    System.currentTimeMillis() - blackListStart);
        return result;
      }
      catch (BlockListConsistencyException e)
      {
        return requestBlackList(all, false);
      }
    }

    // full list
    Set<ByteBuffer> result = processFullBlackList(all, blResult);
    SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                System.currentTimeMillis() - blackListStart);
    return result;
  }

  private Set<ByteBuffer> processDeltaBlackList(boolean all, BlackListResult blResult)
    throws GovManagementException, BlockListConsistencyException
  {
    X509Certificate blackListTrustAnchor = configurationService.getCertificate(dvcaConfiguration.getBlackListTrustAnchorCertificateName());
    if (!checkBlacklistsSignature(blResult.getDeltaAdded(), blackListTrustAnchor)
        || !checkBlacklistsSignature(blResult.getDeltaRemoved(), blackListTrustAnchor))
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_SIGNATURE_CHECK_FAILED);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "signature check of block list failed");
    }
    log.info("Received delta block list");
    if (all)
    {
      Set<ByteBuffer> entityIDs = importBlockListCollectionDelta(new BlackListContent(blResult.getDeltaAdded()),
                                                                 new BlackListContent(blResult.getDeltaRemoved()));
      log.info("Successfully finished requestBlackList for {} terminals", entityIDs.size());
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_RENEWED);
      return entityIDs;
    }

    TerminalPermission tp = facade.getTerminalPermission(cvcRefId);

    ECCVCertificate cvc;
    try
    {
      cvc = new ECCVCertificate(tp.getCvc());
    }
    catch (IOException e)
    {
      log.warn("Could not parse cvc.", e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_PROCESSING_ERROR);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }

    Optional<BlockListHolder> optionalAddList = getBlockListInformation(new BlackListContent(blResult.getDeltaAdded()),
                                                                        cvc.getSectorPublicKeyHash());
    Optional<BlockListHolder> optionalRemoveList = getBlockListInformation(new BlackListContent(blResult.getDeltaRemoved()),
                                                                           cvc.getSectorPublicKeyHash());

    if (optionalRemoveList.isEmpty() || optionalAddList.isEmpty())
    {
      log.warn("Could not parse delta block list parts.");
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_PROCESSING_ERROR);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "Could not parse delta block list parts");
    }

    var blockListId = optionalAddList.get().listId;

    try
    {
      blockListService.updateDeltaBlockList(tp,
                                            blockListId,
                                            optionalAddList.get().specificIDs,
                                            optionalRemoveList.get().specificIDs,
                                            optionalAddList.get().numEntries);
    }
    catch (BlockListStorageException e)
    {
      log.warn("Could not update block list.", e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_PROCESSING_ERROR);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }

    log.info("{}: successfully finished requestBlackList", cvcRefId);

    var sectorID = optionalAddList.get().sectorID;
    Set<ByteBuffer> result = new HashSet<>();
    if (sectorID != null)
    {
      result.add(ByteBuffer.wrap(sectorID));
    }
    SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_RENEWED);
    return result;
  }

  private Optional<BlockListHolder> getBlockListInformation(BlackListContent blackListContent,
                                                            byte[] sectorPublicKeyHash)
  {
    BlackList blackList = new BlackList(blackListContent.getContent());

    var listID = new BigInteger(blackList.getListID()).longValueExact();
    if (blackList.getBlacklistDetails().size() == 1)
    {
      BlackListDetails blackListDetails = blackList.getBlacklistDetails().get(0);
      return Optional.of(new BlockListHolder(listID, blackListDetails.getSectorID(),
                                             blackListDetails.getSectorSpecificIDs(), blackList.getFinalEntries()));
    }


    return blackList.getBlacklistDetails()
                    .stream()
                    .filter(blackListDetails -> MessageDigest.isEqual(blackListDetails.getSectorID(),
                                                                      sectorPublicKeyHash))
                    .map(d -> new BlockListHolder(listID, d.getSectorID(), d.getSectorSpecificIDs(),
                                                  blackList.getFinalEntries()))
                    .findAny();
  }

  private record BlockListHolder(long listId, byte[] sectorID, List<byte[]> specificIDs, Integer numEntries)
  {}


  private Set<ByteBuffer> processFullBlackList(boolean all, BlackListResult blResult) throws GovManagementException
  {
    BlackListContent blackList;
    blackList = downloadBlackList(blResult);
    log.info("Received full block list");
    if (all)
    {
      Set<ByteBuffer> updatedSectorIDs = importBlockListCollection(blackList);
      log.info("Successfully finished requestBlackList for {} terminals", updatedSectorIDs.size());
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_RENEWED);
      return updatedSectorIDs;
    }
    TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
    ECCVCertificate cvc;
    try
    {
      cvc = new ECCVCertificate(tp.getCvc());
    }
    catch (IOException e)
    {
      log.warn("Could not parse cvc.", e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_PROCESSING_ERROR);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }

    Optional<BlockListHolder> optionalEntries = getBlockListInformation(blackList, cvc.getSectorPublicKeyHash());

    if (optionalEntries.isEmpty())
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_PROCESSING_ERROR);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "Could not find corresponding block list entries for terminal %s".formatted(tp.getRefID()));
    }

    BlockListHolder blockListHolder = optionalEntries.get();
    var sectorID = blockListHolder.sectorID;

    try
    {
      blockListService.updateCompleteBlockList(tp, blockListHolder.listId, sectorID, blockListHolder.specificIDs);
    }
    catch (BlockListStorageException e)
    {
      log.warn("Could not update block list.", e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_PROCESSING_ERROR);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }

    log.info("{}: successfully finished requestBlackList", cvcRefId);

    Set<ByteBuffer> result = new HashSet<>();
    if (sectorID != null)
    {
      result.add(ByteBuffer.wrap(sectorID));
    }
    SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_RENEWED);
    return result;
  }

  private BlackListContent downloadBlackList(BlackListResult blResult) throws GovManagementException
  {
    BlackListContent blackList;
    try
    {
      PKIServiceConnector.getContextLock();
      log.debug("{}: block list file download started", cvcRefId);
      PKIServiceConnector connector = dvcaServiceFactory.getPkiServiceConnector(serviceProvider,
                                                                                hsmKeyStore,
                                                                                configurationService.getDvcaConfiguration(serviceProvider),
                                                                                180);
      blackList = new BlackListContent(connector.getFile(blResult.getUri()));
    }
    catch (SocketException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to download block list", e);
      }
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE, blResult.getUri(),
                                       e.getMessage());
    }
    catch (Exception e)
    {
      log.error("{}: cannot download block list", cvcRefId, e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
      log.debug("{}: block list file download finished", cvcRefId);
    }
    X509Certificate blackListTrustAnchor = configurationService.getCertificate(dvcaConfiguration.getBlackListTrustAnchorCertificateName());
    if (!checkBlacklistsSignature(blackList.getContent(), blackListTrustAnchor))
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_SIGNATURE_CHECK_FAILED);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "signature check of block list failed");
    }
    return blackList;
  }

  /**
   * For a given collection of delta block lists, process every single list where the sectorID matches one of the
   * terminals.
   *
   * @param collectionAdded The collection of delta block lists that should be added
   * @param collectionRemoved The collection of delta block lists that should be removed
   * @return A set containing the sectorIDs of the BlackListDetails that matched the refIDs
   * @throws BlockListConsistencyException
   */
  private Set<ByteBuffer> importBlockListCollectionDelta(BlackListContent collectionAdded,
                                                         BlackListContent collectionRemoved)
    throws BlockListConsistencyException
  {
    log.debug("{}: block list parsing for collection started", cvcRefId);
    BlackList parsedBlacklistAdded = new BlackList(collectionAdded.getContent());
    BlackList parsedBlacklistRemoved = new BlackList(collectionRemoved.getContent());
    log.debug("{}: block list parsing for collection finished", cvcRefId);

    // allow gc
    collectionAdded.clear();
    collectionRemoved.clear();

    long blackListIdAdded = new BigInteger(parsedBlacklistAdded.getListID()).longValueExact();
    long blackListIdRemoved = new BigInteger(parsedBlacklistRemoved.getListID()).longValueExact();
    if (blackListIdAdded != blackListIdRemoved)
    {
      log.warn("Received delta lists contain different IDs, refuse to process");
      throw new BlockListConsistencyException();
    }

    if (parsedBlacklistAdded.getFinalEntries() != parsedBlacklistRemoved.getFinalEntries())
    {
      log.warn("Received delta lists contain different numbers of entries, refuse to process");
      throw new BlockListConsistencyException();
    }

    List<String> allRefIDs = facade.getTerminalPermissionRefIDList();
    Map<TerminalPermission, List<byte[]>> addedEntries = buildMapOfSpecificIds(parsedBlacklistAdded, allRefIDs);
    Map<TerminalPermission, List<byte[]>> removedEntries = buildMapOfSpecificIds(parsedBlacklistRemoved, allRefIDs);

    Set<ByteBuffer> result = new HashSet<>();
    for ( Entry<TerminalPermission, List<byte[]>> entry : addedEntries.entrySet() )
    {
      TerminalPermission tp = entry.getKey();
      try
      {
        blockListService.updateDeltaBlockList(tp,
                                              blackListIdAdded,
                                              entry.getValue(),
                                              removedEntries.get(tp) == null ? List.of() : removedEntries.get(tp),
                                              parsedBlacklistAdded.getFinalEntries());
        result.add(ByteBuffer.wrap(tp.getSectorID()));
      }
      catch (BlockListStorageException e)
      {
        log.warn("Could not store block list", e);
      }
      finally
      {
        removedEntries.remove(tp);
      }
    }

    for ( Entry<TerminalPermission, List<byte[]>> entry : removedEntries.entrySet() )
    {
      TerminalPermission tp = entry.getKey();
      try
      {
        blockListService.updateDeltaBlockList(tp,
                                              blackListIdAdded,
                                              List.of(),
                                              entry.getValue(),
                                              parsedBlacklistRemoved.getFinalEntries());
        result.add(ByteBuffer.wrap(tp.getSectorID()));
      }
      catch (BlockListStorageException e)
      {
        log.warn("Could not store block list", e);
      }
    }

    return result;
  }


  private Map<TerminalPermission, List<byte[]>> buildMapOfSpecificIds(BlackList parsedBlacklist, List<String> allRefIDs)
  {
    Map<TerminalPermission, List<byte[]>> map = new HashMap<>();
    parsedBlacklist.getBlacklistDetails().forEach(blacklistDetails -> {
      if (blackListDetailsSectorIDAvailable(blacklistDetails))
      {
        Optional<TerminalPermission> optTp = findSuitableTerminalPermission(blacklistDetails.getSectorID(), allRefIDs);
        if (optTp.isEmpty())
        {
          return;
        }
        map.put(optTp.get(), blacklistDetails.getSectorSpecificIDs());
      }
    });
    return map;
  }

  /**
   * For a given collection of full block lists, process every single list where the sectorID matches one of the
   * terminals.
   *
   * @param blockListCollection The collection of full block lists that should be imported
   * @return A set containing the sectorIDs of the BlackListDetails that matched the refIDs
   */
  private Set<ByteBuffer> importBlockListCollection(BlackListContent blockListCollection)
  {
    Set<ByteBuffer> result = new HashSet<>();
    log.debug("{}: block list parsing for collection started", cvcRefId);
    BlackList parsedBlacklist = new BlackList(blockListCollection.getContent());
    log.debug("{}: block list parsing for collection finished", cvcRefId);

    // allow gc
    blockListCollection.clear();

    List<String> allRefIDs = facade.getTerminalPermissionRefIDList();
    long blackListId = new BigInteger(parsedBlacklist.getListID()).longValueExact();

    parsedBlacklist.getBlacklistDetails().forEach(blacklistDetails -> {
      if (blackListDetailsSectorIDAvailable(blacklistDetails))
      {
        Optional<TerminalPermission> optTp = findSuitableTerminalPermission(blacklistDetails.getSectorID(), allRefIDs);
        if (optTp.isEmpty())
        {
          return;
        }

        TerminalPermission tp = optTp.get();
        log.debug("{}: Writing block list from collection started", tp.getRefID());
        try
        {
          blockListService.updateCompleteBlockList(tp,
                                                   blackListId,
                                                   blacklistDetails.getSectorID(),
                                                   blacklistDetails.getSectorSpecificIDs());
          log.debug("Finished processBlacklistDetails");
          log.debug("{}: Writing block list from collection into DB finished", tp.getRefID());
          result.add(ByteBuffer.wrap(blacklistDetails.getSectorID()));
        }
        catch (BlockListStorageException e)
        {
          log.error("Could not renew block list for terminal %s".formatted(tp.getRefID()), e);
        }
      }
    });
    return result;
  }

  /**
   * Find the {@link TerminalPermission} that matches to the sectorID from the BlackListDetail
   *
   * @param blackListDetailsSectorID the sectorId from the BlackListDetail
   * @param allRefIDs the list of all terminals
   * @return the terminal permission which sectorID matches with the sectorId from the BlackListDetails or empty if the
   *         sectorID from the BlackListDetails is not found
   */
  private Optional<TerminalPermission> findSuitableTerminalPermission(byte[] blackListDetailsSectorID,
                                                                      List<String> allRefIDs)
  {
    // List all terminals
    for ( String refID : allRefIDs )
    {
      // Check that the terminal has a CVC
      TerminalPermission tp = facade.getTerminalPermission(refID);
      byte[] cvcBytes = tp.getCvc();
      if (cvcBytes == null)
      {
        continue;
      }
      try
      {
        ECCVCertificate cvc = new ECCVCertificate(cvcBytes);
        // Compare the sectorID from the BlackList and given terminal
        if (Arrays.equals(blackListDetailsSectorID, cvc.getSectorPublicKeyHash()))
        {
          return Optional.of(tp);
        }
      }
      catch (IOException e)
      {
        log.warn(UNABLE_TO_PARSE_GIVEN_CVC + " for terminal " + tp.getRefID(), e);
      }
    }
    return Optional.empty();
  }

  /**
   * Check that for a given BlackListDetail the sectorID is not null or empty
   *
   * @param blacklistDetails the BlackListDetail to be checked
   * @return true if the sectorID of the given BlackListDetail is not null and not empty
   */
  private boolean blackListDetailsSectorIDAvailable(BlackListDetails blacklistDetails)
  {
    return blacklistDetails.getSectorID() != null && blacklistDetails.getSectorID().length > 0;
  }

  /**
   * Verify signature of a block list
   */
  private boolean checkBlacklistsSignature(byte[] blacklist, X509Certificate trustAnchor)
  {
    try
    {
      new CmsSignatureChecker(trustAnchor).checkEnvelopedSignature(blacklist);
      return true;
    }
    catch (SignatureException | CMSException e)
    {
      log.debug("Signature check on block list not successful", e);
      return false;
    }
  }

  /**
   * This class should be the only place where the blacklist byte array is referenced for a longer time so it can be
   * gc'ed as soon as possible
   */
  @AllArgsConstructor
  static final class BlackListContent
  {

    @Getter
    private byte[] content;

    /**
     * Call this method to allow garbage collection of the blacklist byte array
     */
    private void clear()
    {
      content = null;
    }
  }
}
