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

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.cms.CMSException;

import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.server.idprovider.accounting.SNMPDelegate;
import de.governikus.eumw.poseidas.server.idprovider.accounting.SNMPDelegate.OID;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.SslKeysDto;
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

    BerCaPolicy policy = PolicyImplementationFactory.getInstance().getPolicy(pkiConfig.getBerCaPolicyId());
    if (policy.hasPassiveAuthService())
    {
      try
      {
        PKIServiceConnector.getContextLock();
        log.debug("{}: obtained lock on SSL context for downloading master and defect list", cvcRefId);
        PassiveAuthServiceWrapper wrapper = createWrapper();
        masterList = getMasterList(wrapper);
        defectList = getDefectList(wrapper);
        if (masterList != null)
        {
          log.debug("MasterList:\n{}", Base64.getMimeEncoder().encodeToString(masterList));
        }
        if (defectList != null)
        {
          log.debug("DefectList:\n{}", Base64.getMimeEncoder().encodeToString(defectList));
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
      catch (Throwable t)
      {
        log.error("{}: cannot renew master and defect list", cvcRefId, t);
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
        masterList = Arrays.copyOf(tp.getMasterList(), tp.getMasterList().length);
        defectList = Arrays.copyOf(tp.getDefectList(), tp.getDefectList().length);
      }
      catch (Throwable t)
      {
        log.error("{}: cannot fetch master and defect list", cvcRefId, t);
        throw new GovManagementException(GlobalManagementCodes.INTERNAL_ERROR);
      }
    }
    if (masterList != null)
    {
      facade.storeMasterList(cvcRefId, masterList);
    }
    if (defectList != null)
    {
      facade.storeDefectList(cvcRefId, defectList);
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

  private byte[] getMasterList(PassiveAuthServiceWrapper wrapper) throws MalformedURLException
  {
    byte[] masterList = wrapper.getMasterList();
    if (!isLocalZip(masterList))
    {
      CmsSignatureChecker checker = new CmsSignatureChecker(pkiConfig.getMasterListTrustAnchor());
      try
      {
        checker.checkEnvelopedSignature(masterList);
      }
      catch (SignatureException | CMSException e)
      {
        SNMPDelegate.getInstance()
                    .sendSNMPTrap(OID.MASTERLIST_SIGNATURE_WRONG,
                                  SNMPDelegate.MASTERLIST_SIGNATURE_WRONG + " "
                                                                  + "signature check for master list failed");
        log.debug("Signature check on master list not successful", e);
        return null;
      }
    }
    return masterList;
  }

  private byte[] getDefectList(PassiveAuthServiceWrapper wrapper) throws MalformedURLException
  {

    byte[] defectList = wrapper.getDefectList();
    if (!isLocalZip(defectList))
    {
      CmsSignatureChecker checker = new CmsSignatureChecker(pkiConfig.getDefectListTrustAnchor());
      try
      {
        checker.checkEnvelopedSignature(defectList);
      }
      catch (SignatureException | CMSException e)
      {
        SNMPDelegate.getInstance()
                    .sendSNMPTrap(OID.DEFECTLIST_SIGNATURE_WRONG,
                                  SNMPDelegate.DEFECTLIST_SIGNATURE_WRONG + " "
                                                                  + "signature check for defect list failed");
        log.debug("Signature check on defect list not successful", e);
        return null;
      }
    }
    return defectList;
  }

  private boolean isLocalZip(byte[] data) throws MalformedURLException
  {
    String host = new URL(pkiConfig.getPassiveAuthService().getUrl()).getHost();
    return data.length >= 2 && data[0] == 0x50 && data[1] == 0X4b
           && ("localhost".equals(host) || "127.0.0.1".equals(host));
  }
}
