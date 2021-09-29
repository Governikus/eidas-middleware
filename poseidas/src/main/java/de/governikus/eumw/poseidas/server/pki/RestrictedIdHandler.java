/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cms.CMSException;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.cardbase.crypto.DigestUtil;
import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.BlackList;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.BlackListDetails;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.SslKeysDto;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdServiceWrapper;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.RestrictedIdServiceWrapper.BlackListResult;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.ServiceWrapperFactory;
import lombok.extern.slf4j.Slf4j;


/**
 * Process of requesting public sector key and black list
 *
 * @author tautenhahn, hme
 */
@Slf4j
public class RestrictedIdHandler extends BerCaRequestHandlerBase
{

  private static final String UNABLE_TO_PARSE_GIVEN_CVC = "unable to parse given cvc";

  private PKIServiceConnector connector;

  /**
   * Create instance for one-time use. May be re-used only for same configuration version.
   *
   * @param nPaConf
   * @param facade
   */
  RestrictedIdHandler(EPAConnectorConfigurationDto nPaConf, TerminalPermissionAO facade, KeyStore hsmKeyStore)
    throws GovManagementException
  {
    super(nPaConf, facade, hsmKeyStore);
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
        throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("no sector public key hash in the blacklist or cvc found for entry "
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
   * @return The digest algorithm that was used in the public key of the CVC or SHA-256 if the public key
   *         digest algorithm could not be determined
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
      RestrictedIdServiceWrapper wrapper = createWrapper();
      sectorPK = wrapper.getSectorPublicKey(sectorId);
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
    }
    facade.storePublicSectorKey(cvcRefId, sectorPK);
  }

  /**
   * This class should be the only place where the blacklist byte array is referenced for a longer time so it
   * can be gc'ed as soon as possible
   */
  static final class BlackListContent
  {

    private byte[] content;

    /**
     * Create a new instance to reference the blacklist byte array
     *
     * @param content the blacklist byte array
     */
    private BlackListContent(byte[] content)
    {
      super();
      this.content = content;
    }

    /**
     * Get the blacklist byte array
     */
    public byte[] getContent()
    {
      return content;
    }

    /**
     * Call this method to allow garbage collection of the blacklist byte array
     */
    private void clear()
    {
      content = null;
    }
  }

  /**
   * request a black list and store it in the database
   *
   * @param all <code>true</code> to store the blacklist for all service providers contained,
   *          <code>false</code> to store only the one for the provider referred by the entityID of this
   *          instance
   * @return The sectors the blacklist was renewed for.
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
      log.debug("{}: obtained lock on SSL context for downloading black list", cvcRefId);
      RestrictedIdServiceWrapper wrapper = createWrapper();

      blackListStart = System.currentTimeMillis();
      byte[] deltaID = null;
      if (delta)
      {
        log.debug("{}: trying to request delta blacklist", cvcRefId);
        TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
        deltaID = tp.getBlackListVersion() == null ? null
          : BigInteger.valueOf(tp.getBlackListVersion()).toByteArray();
      }

      blResult = wrapper.getBlacklistResult(deltaID);
    }
    catch (GovManagementException e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw e;
    }
    catch (Exception e)
    {
      log.error("{}: cannot download black list", cvcRefId, e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE,
                                       pkiConfig.getRestrictedIdService().getUrl(), e.getLocalizedMessage());
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
      log.debug("{}: BlackList request done", cvcRefId);
    }
    if (blResult == null || (blResult.getUri() == null && blResult.getDeltaAdded() == null))
    {
      log.info("{}: Did not receive a blacklist from BerCa", cvcRefId);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      return new HashSet<>();
    }
    if (RestrictedIdServiceWrapper.NO_NEW_DATA.equals(blResult))
    {
      log.info("{}: No newer delta blacklist from BerCa available", cvcRefId);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_RENEWED);
      facade.updateBlackListStoreDate(cvcRefId, null, null);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                  System.currentTimeMillis() - blackListStart);
      return new HashSet<>();
    }

    // No URI means we received a delta list
    if (blResult.getUri() != null)
    {
      Set<ByteBuffer> result = processFullBlackList(all, blResult);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                  System.currentTimeMillis() - blackListStart);
      return result;
    }
    else
    {
      Set<ByteBuffer> result = processDeltaBlackList(all, blResult);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                  System.currentTimeMillis() - blackListStart);
      return result;
    }
  }

  private Set<ByteBuffer> processDeltaBlackList(boolean all, BlackListResult blResult)
    throws GovManagementException
  {
    if (!checkBlacklistsSignature(blResult.getDeltaAdded(), pkiConfig.getBlackListTrustAnchor())
        || !checkBlacklistsSignature(blResult.getDeltaRemoved(), pkiConfig.getBlackListTrustAnchor()))
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_SIGNATURE_CHECK_FAILED);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "signature check of black list failed");
    }
    log.info("Received delta blacklist");
    if (all)
    {
      Set<ByteBuffer> entityIDs = importBlacklistCollection(new BlackListContent(blResult.getDeltaRemoved()),
                                                            BlackList.TYPE_REMOVED);
      entityIDs.addAll(importBlacklistCollection(new BlackListContent(blResult.getDeltaAdded()),
                                                 BlackList.TYPE_ADDED));
      log.info("Successfully finished requestBlackList for {} terminals", entityIDs.size());
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_RENEWED);
      return entityIDs;
    }
    else
    {
      TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
      try
      {
        ECCVCertificate cvc = new ECCVCertificate(tp.getCvc());
        importBlackList(new BlackListContent(blResult.getDeltaRemoved()),
                        cvcRefId,
                        cvc.getSectorPublicKeyHash(),
                        BlackList.TYPE_REMOVED);
        byte[] sectorID = importBlackList(new BlackListContent(blResult.getDeltaAdded()),
                                          cvcRefId,
                                          cvc.getSectorPublicKeyHash(),
                                          BlackList.TYPE_ADDED);
        log.info("{}: successfully finished requestBlackList", cvcRefId);

        Set<ByteBuffer> result = new HashSet<>();
        if (sectorID != null)
        {
          result.add(ByteBuffer.wrap(sectorID));
        }
        SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                    SNMPConstants.LIST_RENEWED);
        return result;
      }
      catch (IOException e)
      {
        SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                    SNMPConstants.LIST_PROCESSING_ERROR);
        throw new IllegalArgumentException(UNABLE_TO_PARSE_GIVEN_CVC, e);
      }
    }
  }

  private Set<ByteBuffer> processFullBlackList(boolean all, BlackListResult blResult)
    throws GovManagementException
  {
    BlackListContent blackList;
    blackList = downloadBlackList(blResult);
    log.info("Received full blacklist");
    if (all)
    {
      Set<ByteBuffer> updatedSectorIDs = importBlacklistCollection(blackList, BlackList.TYPE_COMPLETE);
      log.info("Successfully finished requestBlackList for {} terminals", updatedSectorIDs.size());
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_RENEWED);
      return updatedSectorIDs;
    }
    TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
    try
    {
      ECCVCertificate cvc = new ECCVCertificate(tp.getCvc());
      byte[] sectorID = importBlackList(blackList,
                                        cvcRefId,
                                        cvc.getSectorPublicKeyHash(),
                                        BlackList.TYPE_COMPLETE);
      log.info("{}: successfully finished requestBlackList", cvcRefId);

      Set<ByteBuffer> result = new HashSet<>();
      if (sectorID != null)
      {
        result.add(ByteBuffer.wrap(sectorID));
      }
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_RENEWED);
      return result;
    }
    catch (IOException e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_PROCESSING_ERROR);
      throw new IllegalArgumentException(UNABLE_TO_PARSE_GIVEN_CVC, e);
    }
  }

  private BlackListContent downloadBlackList(BlackListResult blResult) throws GovManagementException
  {
    BlackListContent blackList;
    try
    {
      PKIServiceConnector.getContextLock();
      log.debug("{}: Blacklist file download started", cvcRefId);
      blackList = new BlackListContent(connector.getFile(blResult.getUri()));
    }
    catch (SocketException e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE,
                                       blResult.getUri(), e.getMessage());
    }
    catch (Exception e)
    {
      log.error("{}: cannot download black list", cvcRefId, e);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
      log.debug("{}: Blacklist file download finished", cvcRefId);
    }
    if (!checkBlacklistsSignature(blackList.getContent(), pkiConfig.getBlackListTrustAnchor()))
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_SIGNATURE_CHECK_FAILED);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR,
                                       "signature check of black list failed");
    }
    return blackList;
  }

  /**
   * For a given blackListCollection, process every contained BlackListDetails which's sectorID matches to one
   * of the terminals
   *
   * @param blacklistCollection The BlackListCollection that should be imported
   * @param type The action that should be performed with the contained BlackListEntries
   * @return A set containing the sectorIDs of the BlackListDetails that matched the refIDs.
   */
  private Set<ByteBuffer> importBlacklistCollection(BlackListContent blacklistCollection, int type)
  {
    Set<ByteBuffer> result = new HashSet<>();
    log.debug("{}: Blacklist parsing for collection started", cvcRefId);
    BlackList parsedBlacklist = new BlackList(blacklistCollection.getContent());
    log.debug("{}: Blacklist parsing for collection finished", cvcRefId);

    // allow gc
    blacklistCollection.clear();

    List<String> allRefIDs = facade.getTerminalPermissionRefIDList();
    long blackListId = new BigInteger(parsedBlacklist.getListID()).longValue();

    List<BlackListDetails> detailsList = parsedBlacklist.getBlacklistDetails();
    while (!detailsList.isEmpty())
    {
      BlackListDetails blacklistDetails = detailsList.remove(0);
      if (blackListDetailsSectorIDAvailable(blacklistDetails))
      {
        String refID = findSuitableRefID(blacklistDetails.getSectorID(), allRefIDs);
        if (refID != null)
        {
          TerminalPermission tp = facade.getTerminalPermission(refID);
          log.debug("{}: Writing blacklist from collection into DB started", tp.getRefID());
          processBlacklistDetails(type, blacklistDetails, refID);
          log.debug("Finished processBlacklistDetails");
          facade.updateBlackListStoreDate(refID, blacklistDetails.getSectorID(), blackListId);
          log.debug("{}: Writing blacklist from collection into DB finished", tp.getRefID());
          result.add(ByteBuffer.wrap(blacklistDetails.getSectorID()));
        }
      }
    }
    return result;
  }

  /**
   * Find the refID that matches to the sectorID from the BlackListDetail
   *
   * @param blackListDetailsSectorID the sectorId from the BlackListDetail
   * @param allRefIDs the list of all terminals
   * @return the refId of the terminal which sectorID matches with the sectorId from the BlackListDetails or
   *         null if the sectorID from the BlackListDetails is not found
   */
  private String findSuitableRefID(byte[] blackListDetailsSectorID, List<String> allRefIDs)
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
          return refID;
        }
      }
      catch (IOException e)
      {
        throw new IllegalArgumentException(UNABLE_TO_PARSE_GIVEN_CVC, e);
      }
    }
    return null;
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

  private void processBlacklistDetails(int type, BlackListDetails blacklistDetails, String refID)
  {
    log.debug("blacklist contains {} entries.", blacklistDetails.getSectorSpecificIDs().size());
    if (type == BlackList.TYPE_COMPLETE)
    {
      facade.replaceBlackList(refID, blacklistDetails.getSectorID(), blacklistDetails.getSectorSpecificIDs());
    }
    else if (type == BlackList.TYPE_ADDED)
    {
      facade.addBlackListEntries(blacklistDetails.getSectorID(), blacklistDetails.getSectorSpecificIDs());
    }
    else if (type == BlackList.TYPE_REMOVED)
    {
      facade.removeBlackListEntries(refID,
                                    blacklistDetails.getSectorID(),
                                    blacklistDetails.getSectorSpecificIDs());
    }
  }

  /**
   * put a given black list into data storage
   *
   * @param blackList
   * @param cvcRefId
   * @param sectorPublicKeyHash
   * @return true if the riKey1 has to be replaced with a new one.
   * @throws GovManagementException
   */
  private byte[] importBlackList(BlackListContent blackList,
                                 String cvcRefId,
                                 byte[] sectorPublicKeyHash,
                                 int type)
  {
    if (blackList == null)
    {
      log.error("{}:The blacklist did not contain a part suitable for this cvcRefId", cvcRefId);
      return null;
    }

    log.debug("{}: Blacklist parsing started", cvcRefId);
    BlackList parsedBlacklist = new BlackList(blackList.getContent());
    log.debug("{}: Blacklist parsing finished", cvcRefId);

    // the byte array is no longer needed, allow gc
    blackList.clear();

    long blackListId = new BigInteger(parsedBlacklist.getListID()).longValue();

    List<BlackListDetails> detailsList = parsedBlacklist.getBlacklistDetails();

    if (detailsList != null)
    {
      // if there is only one blacklist, it is assumed that this list belongs to this provider
      if (detailsList.size() == 1)
      {
        BlackListDetails blackListDetails = detailsList.get(0);
        log.debug("{}: Writing single blacklist into DB started", cvcRefId);
        processBlacklistDetails(type, blackListDetails, cvcRefId);
        log.debug("Finished processBlacklistDetails");
        facade.updateBlackListStoreDate(cvcRefId, blackListDetails.getSectorID(), blackListId);
        log.debug("{}: Writing single blacklist into DB finished", cvcRefId);
        return blackListDetails.getSectorID();
      }

      // if there are more, we must search for the right one
      while (!detailsList.isEmpty())
      {
        // while...remove allows for the gc to dispose of the blacklistdetails already passed
        BlackListDetails blacklistDetails = detailsList.remove(0);
        if (blackListDetailsSectorIDAvailable(blacklistDetails))
        {
          log.debug("{}: checking blacklist details", cvcRefId);
          // Beware that theoretically the sectorID and the sectorPublicKeyHash of the same provider could
          // differ in which case this would not work anymore!
          if (MessageDigest.isEqual(blacklistDetails.getSectorID(), sectorPublicKeyHash))
          {
            log.debug("{}: Writing single blacklist from collection into DB started", cvcRefId);
            processBlacklistDetails(type, blacklistDetails, cvcRefId);
            facade.updateBlackListStoreDate(cvcRefId, blacklistDetails.getSectorID(), blackListId);
            log.debug("{}: Writing single blacklist from collection into DB finished", cvcRefId);
            return blacklistDetails.getSectorID();
          }
        }
      }
    }
    log.error("{}:The blacklist did not contain a part suitable for this cvcRefId", cvcRefId);
    SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.BLACKLIST_TRAP_LAST_RENEWAL_STATUS,
                                SNMPConstants.LIST_PROCESSING_ERROR);
    return null;
  }

  private RestrictedIdServiceWrapper createWrapper() throws GovManagementException
  {
    PkiServiceType serviceData = pkiConfig.getRestrictedIdService();
    String serviceUrl = serviceData.getUrl();
    SslKeysDto keys = pkiConfig.getSslKeys().get(serviceData.getSslKeysId());
    BerCaPolicy policy = PolicyImplementationFactory.getInstance().getPolicy(pkiConfig.getBerCaPolicyId());
    String wsdlVersion = policy.getWsdlVersionRestrictedID();

    try
    {
      if (hsmKeyStore == null)
      {
        connector = new PKIServiceConnector(180, keys.getServerCertificate(), keys.getClientKey(),
                                            keys.getClientCertificateChain(), cvcRefId);
      }
      else
      {
        connector = new PKIServiceConnector(180, keys.getServerCertificate(), hsmKeyStore, null, cvcRefId);
      }
      return ServiceWrapperFactory.createRestrictedIdServiceWrapper(connector, serviceUrl, wsdlVersion);
    }
    catch (GeneralSecurityException e)
    {
      log.error("{}: problem with crypto data of this SP", cvcRefId, e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }

  /**
   * Verify signature of a black list
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
      log.debug("Signature check on blacklist not successful", e);
      return false;
    }
  }
}
