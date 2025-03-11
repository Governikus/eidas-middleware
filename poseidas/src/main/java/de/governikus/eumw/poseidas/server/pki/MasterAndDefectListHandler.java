/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.net.MalformedURLException;
import java.security.KeyStore;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.cms.CMSException;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.eidserver.crl.CertificationRevocationListImpl;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants.TrapOID;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PassiveAuthService;
import lombok.extern.slf4j.Slf4j;


/**
 * Process of getting and storing the master and defect lists.
 *
 * @author tautenhahn, hme
 */
@Slf4j
public class MasterAndDefectListHandler extends BerCaRequestHandlerBase
{

  /**
   * Create new instance for current configuration
   *
   * @param facade must be obtained by client
   */
  MasterAndDefectListHandler(ServiceProviderType nPaConf,
                             TerminalPermissionAO facade,
                             KeyStore hsmKeyStore,
                             ConfigurationService configurationService)
    throws GovManagementException
  {
    super(nPaConf, facade, hsmKeyStore, configurationService);
  }

  /**
   * Get and
   *
   * @throws GovManagementException
   */
  void updateLists() throws GovManagementException
  {
    PassiveAuthService service = dvcaServiceFactory.passiveAuthService(serviceProvider, hsmKeyStore);
    MasterList masterList;
    byte[] defectList;

    try
    {
      masterList = updateMasterList(service);
      if (CertificationRevocationListImpl.isInitialized())
      {
        CertificationRevocationListImpl.getInstance().updateMasterlist(masterList.getCertificates());
      }
    }
    catch (MalformedURLException e)
    {
      log.error("{}: Can not parse service URL", cvcRefId, e);
      throw new MasterAndDefectListException(GlobalManagementCodes.INTERNAL_ERROR,
                                             MasterAndDefectListException.MasterOrDefectList.MASTER_LIST);
    }

    try
    {
      defectList = updateDefectList(service, masterList);
      if (defectList == null)
      {
        throw new MasterAndDefectListException(GlobalManagementCodes.INTERNAL_ERROR,
                                               MasterAndDefectListException.MasterOrDefectList.DEFECT_LIST);
      }
    }
    catch (MalformedURLException e)
    {
      log.error("{}: Can not parse service URL", cvcRefId, e);
      throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
    }
  }

  private byte[] updateDefectList(PassiveAuthService service, MasterList ml) throws MalformedURLException
  {
    PKIServiceConnector.getContextLock();
    log.debug("{}: obtained lock on SSL context for downloading defect list", cvcRefId);

    try
    {
      long defectListStart = System.currentTimeMillis();
      byte[] defectList = getDefectList(service, ml);
      if (defectList != null)
      {
        log.trace("DefectList:\n{}", Base64.getMimeEncoder().encodeToString(defectList));
        facade.storeDefectList(cvcRefId, defectList);
        SNMPTrapSender.sendSNMPTrap(TrapOID.DEFECTLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                    System.currentTimeMillis() - defectListStart);
      }
      return defectList;
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
    }
  }

  private MasterList updateMasterList(PassiveAuthService service) throws MalformedURLException
  {
    PKIServiceConnector.getContextLock();
    log.debug("{}: obtained lock on SSL context for downloading master list", cvcRefId);

    try
    {
      long masterListStart = System.currentTimeMillis();
      byte[] masterListBytes = getMasterList(service);
      MasterList masterList;
      if (masterListBytes == null)
      {
        // if we do not get a new master list from CA, at least try to use old stored version for defect
        // list check
        masterList = new MasterList(facade.getTerminalPermission(cvcRefId).getMasterList());
      }
      else
      {
        log.trace("MasterList:\n{}", Base64.getMimeEncoder().encodeToString(masterListBytes));
        masterList = new MasterList(masterListBytes);
        facade.storeMasterList(cvcRefId, masterListBytes);
        SNMPTrapSender.sendSNMPTrap(TrapOID.MASTERLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                    System.currentTimeMillis() - masterListStart);
      }
      return masterList;
    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
    }
  }

  byte[] getMasterList(PassiveAuthService service) throws MalformedURLException
  {
    byte[] masterListBytes = service.getMasterList();
    if (masterListBytes == null)
    {
      SNMPTrapSender.sendSNMPTrap(TrapOID.MASTERLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_NOT_RECEIVED);
      return null;
    }

    byte[] masterListFromTerminalPermission = facade.getTerminalPermission(cvcRefId).getMasterList();
    if (ArrayUtil.isNullOrEmpty(masterListFromTerminalPermission)
        || !checkWithMasterListAsTrustAnchorSuccessful(masterListBytes, masterListFromTerminalPermission))
    {
      try
      {
        X509Certificate masterListTrustAnchor = configurationService.getCertificate(dvcaConfiguration.getMasterListTrustAnchorCertificateName());
        CmsSignatureChecker checker = new CmsSignatureChecker(masterListTrustAnchor);
        checker.checkEnvelopedSignature(masterListBytes);
      }
      catch (SignatureException | CMSException e)
      {
        SNMPTrapSender.sendSNMPTrap(TrapOID.MASTERLIST_TRAP_LAST_RENEWAL_STATUS,
                                    SNMPConstants.LIST_SIGNATURE_CHECK_FAILED);
        log.debug("Signature check on master list with trust anchor from configuration not successful", e);
        return null;
      }
    }
    SNMPTrapSender.sendSNMPTrap(TrapOID.MASTERLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_RENEWED);
    log.debug("Successfully received master list");
    return masterListBytes;
  }

  private boolean checkWithMasterListAsTrustAnchorSuccessful(byte[] masterList, byte[] masterListFromTerminalPermission)
  {
    try
    {
      CmsSignatureChecker checker = new CmsSignatureChecker(new MasterList(masterListFromTerminalPermission).getCertificates());
      checker.checkEnvelopedSignature(masterList);
      return true;
    }
    catch (SignatureException | CMSException e)
    {
      log.debug("Signature check on master list with master list as trust anchor not successful", e);
      return false;
    }
  }

  private byte[] getDefectList(PassiveAuthService service, MasterList ml) throws MalformedURLException
  {

    byte[] defectList = service.getDefectList();
    if (defectList == null)
    {
      SNMPTrapSender.sendSNMPTrap(TrapOID.DEFECTLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_NOT_RECEIVED);
      return null;
    }

    CmsSignatureChecker checker = new CmsSignatureChecker(ml.getCertificates());
    try
    {
      checker.checkEnvelopedSignature(defectList);
    }
    catch (SignatureException | CMSException e)
    {
      SNMPTrapSender.sendSNMPTrap(TrapOID.DEFECTLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_SIGNATURE_CHECK_FAILED);
      log.debug("Signature check on defect list not successful", e);
      return null;
    }
    SNMPTrapSender.sendSNMPTrap(TrapOID.DEFECTLIST_TRAP_LAST_RENEWAL_STATUS, SNMPConstants.LIST_RENEWED);
    log.debug("Successfully received defect list");
    return defectList;
  }
}
