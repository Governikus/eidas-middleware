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

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.cms.CMSException;

import de.governikus.eumw.poseidas.cardbase.ArrayUtil;
import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.eidserver.model.signeddata.MasterList;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.SslKeysDto;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants.TrapOID;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PassiveAuthServiceWrapper;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.ServiceWrapperFactory;
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
  MasterAndDefectListHandler(EPAConnectorConfigurationDto nPaConf,
                             TerminalPermissionAO facade,
                             KeyStore hsmKeyStore)
    throws GovManagementException
  {
    super(nPaConf, facade, hsmKeyStore);
  }

  /**
   * Get and
   *
   * @throws GovManagementException
   */
  void updateLists() throws GovManagementException
  {
    byte[] masterList = null;
    byte[] defectList = null;

    long masterListStart;
    long defectListStart;

    BerCaPolicy policy = PolicyImplementationFactory.getInstance().getPolicy(pkiConfig.getBerCaPolicyId());
    if (policy.hasPassiveAuthService())
    {
      try
      {
        PKIServiceConnector.getContextLock();
        log.debug("{}: obtained lock on SSL context for downloading master and defect list", cvcRefId);
        PassiveAuthServiceWrapper wrapper = createWrapper();

        masterListStart = System.currentTimeMillis();
        masterList = getMasterList(wrapper);
        MasterList ml;
        if (masterList == null)
        {
          // if we do not get a new master list from CA, at least try to use old stored version for defect
          // list check
          ml = new MasterList(facade.getTerminalPermission(cvcRefId).getMasterList());
        }
        else
        {
          log.trace("MasterList:\n{}", Base64.getMimeEncoder().encodeToString(masterList));
          ml = new MasterList(masterList);
        }

        defectListStart = System.currentTimeMillis();
        defectList = getDefectList(wrapper, ml);
        if (defectList != null)
        {
          log.trace("DefectList:\n{}", Base64.getMimeEncoder().encodeToString(defectList));
        }
      }
      catch (MalformedURLException e)
      {
        log.error("{}: Can not parse service URL", cvcRefId, e);
        throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
      }
      catch (GovManagementException e)
      {
        throw e;
      }
      catch (Exception e)
      {
        log.error("{}: cannot renew master and defect list", cvcRefId, e);
        throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
      }
      finally
      {
        PKIServiceConnector.releaseContextLock();
      }
    }
    else
    {
      try
      {
        // unsupported master and defect list service so we "emulate" it
        TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
        masterListStart = System.currentTimeMillis();
        masterList = Arrays.copyOf(tp.getMasterList(), tp.getMasterList().length);
        defectListStart = System.currentTimeMillis();
        defectList = Arrays.copyOf(tp.getDefectList(), tp.getDefectList().length);
      }
      catch (Exception e)
      {
        log.error("{}: cannot fetch master and defect list", cvcRefId, e);
        throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
      }
    }
    if (masterList != null)
    {
      facade.storeMasterList(cvcRefId, masterList);
      SNMPTrapSender.sendSNMPTrap(TrapOID.MASTERLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                  System.currentTimeMillis() - masterListStart);
    }
    if (defectList != null)
    {
      facade.storeDefectList(cvcRefId, defectList);
      SNMPTrapSender.sendSNMPTrap(TrapOID.DEFECTLIST_TRAP_LAST_RENEWAL_PROCESSING_DURATION,
                                  System.currentTimeMillis() - defectListStart);
    }
    if (masterList == null || defectList == null)
    {
      throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
    }
  }

  private PassiveAuthServiceWrapper createWrapper() throws GovManagementException
  {
    PkiServiceType serviceData = pkiConfig.getPassiveAuthService();
    String serviceUrl = serviceData.getUrl();
    SslKeysDto keys = pkiConfig.getSslKeys().get(serviceData.getSslKeysId());
    String version = PolicyImplementationFactory.getInstance()
                                                .getPolicy(pkiConfig.getBerCaPolicyId())
                                                .getWsdlVersionPassiveAuth();

    try
    {
      PKIServiceConnector connector;
      if (hsmKeyStore == null)
      {
        connector = new PKIServiceConnector(60, keys.getServerCertificate(), keys.getClientKey(),
                                            keys.getClientCertificateChain(), cvcRefId);
      }
      else
      {
        connector = new PKIServiceConnector(60, keys.getServerCertificate(), hsmKeyStore, null, cvcRefId);
      }
      return ServiceWrapperFactory.createPassiveAuthServiceWrapper(connector, serviceUrl, version);
    }
    catch (GeneralSecurityException e)
    {
      log.error("{}: problem with crypto data of SP", cvcRefId, e);
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, e.getMessage());
    }
    catch (URISyntaxException e)
    {
      throw new GovManagementException(IDManagementCodes.INVALID_URL, "ID.value.service.termAuth.url");
    }
  }

  byte[] getMasterList(PassiveAuthServiceWrapper wrapper) throws MalformedURLException
  {
    byte[] masterList = wrapper.getMasterList();
    if (masterList == null)
    {
      SNMPTrapSender.sendSNMPTrap(TrapOID.MASTERLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      return null;
    }
    else if (!isLocalZip(masterList))
    {
      byte[] masterListFromTerminalPermission = facade.getTerminalPermission(cvcRefId).getMasterList();
      if (ArrayUtil.isNullOrEmpty(masterListFromTerminalPermission)
          || !checkWithMasterListAsTrustAnchorSuccessful(masterList, masterListFromTerminalPermission))
      {
        try
        {
          CmsSignatureChecker checker = new CmsSignatureChecker(pkiConfig.getMasterListTrustAnchor());
          checker.checkEnvelopedSignature(masterList);
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
    }
    log.debug("Successfully received master list");
    return masterList;
  }

  private boolean checkWithMasterListAsTrustAnchorSuccessful(byte[] masterList,
                                                             byte[] masterListFromTerminalPermission)
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

  private byte[] getDefectList(PassiveAuthServiceWrapper wrapper, MasterList ml) throws MalformedURLException
  {

    byte[] defectList = wrapper.getDefectList();
    if (defectList == null)
    {
      SNMPTrapSender.sendSNMPTrap(TrapOID.DEFECTLIST_TRAP_LAST_RENEWAL_STATUS,
                                  SNMPConstants.LIST_NOT_RECEIVED);
      return null;
    }
    else if (!isLocalZip(defectList))
    {
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
    }
    log.debug("Successfully received defect list");
    return defectList;
  }

  private boolean isLocalZip(byte[] data) throws MalformedURLException
  {
    if (data == null || data.length <= 0)
    {
      return false;
    }
    String host = new URL(pkiConfig.getPassiveAuthService().getUrl()).getHost();
    return data.length >= 2 && data[0] == 0x50 && data[1] == 0X4b
           && ("localhost".equals(host) || "127.0.0.1".equals(host));
  }
}
