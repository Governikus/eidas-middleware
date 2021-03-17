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
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import de.governikus.eumw.poseidas.server.idprovider.config.CoreConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.EPAConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PkiConnectorConfigurationDto;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import de.governikus.eumw.poseidas.server.idprovider.config.ServiceProviderDto;
import de.governikus.eumw.poseidas.server.idprovider.config.SslKeysDto;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation using the EJB facade.
 */
@Component("PermissionDataHandling")
@Scope("singleton")
@Slf4j
public class PermissionDataHandling implements PermissionDataHandlingMBean
{

  private static final String NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE = "{}: no terminal permission entry available";

  private static final String ID_CONNECTOR_CONFIGURATION = "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.";

  @Autowired
  protected HSMServiceHolder hsmServiceHolder;

  @Autowired
  private TerminalPermissionAO facade;

  @Autowired
  private EIDInternal eidInternal;

  private CVCRequestHandler getCvcRequestHandler(EPAConnectorConfigurationDto nPaConf) throws GovManagementException
  {
    return new CVCRequestHandler(nPaConf, facade, hsmServiceHolder.getKeyStore());
  }

  private EPAConnectorConfigurationDto getnPaConfig(String entityID) throws GovManagementException
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    if (config == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage());
    }
    ServiceProviderDto prov = config.getServiceProvider().get(entityID);
    if (prov == null)
    {
      throw new GovManagementException(IDManagementCodes.SERVICE_PROVIDER_NOT_SAVED.createMessage());
    }
    EPAConnectorConfigurationDto npaConf = prov.getEpaConnectorConfiguration();
    if (npaConf == null)
    {
      throw new GovManagementException(IDManagementCodes.SERVICE_PROVIDER_NOT_SAVED.createMessage());
    }
    return npaConf;
  }

  private EPAConnectorConfigurationDto getnPaConfigWithCheck(String entityID) throws GovManagementException
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    if (config == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage());
    }
    ServiceProviderDto prov = config.getServiceProvider().get(entityID);
    return getnPaConfigWithCheck(prov);
  }

  private EPAConnectorConfigurationDto getnPaConfigWithCheck(ServiceProviderDto prov) throws GovManagementException
  {
    if (prov == null)
    {
      throw new GovManagementException(IDManagementCodes.SERVICE_PROVIDER_NOT_SAVED.createMessage());
    }
    EPAConnectorConfigurationDto npaConf = prov.getEpaConnectorConfiguration();
    if (npaConf == null)
    {
      throw new GovManagementException(IDManagementCodes.SERVICE_PROVIDER_NOT_SAVED.createMessage());
    }
    if (!npaConf.isUpdateCVC())
    {
      throw new GovManagementException(IDManagementCodes.INVALID_INPUT_DATA.createMessage("service provider flag updateCVC is set to false "
                                                                                          + npaConf.getCVCRefID()));
    }
    return npaConf;
  }

  @Override
  public ManagementMessage removePermissionData(String cvcRefId)
  {
    facade.remove(cvcRefId);
    return null;
  }

  @Override
  public ManagementMessage renewMasterAndDefectList(String entityID)
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    if (config == null)
    {
      return GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage();
    }
    try
    {
      ServiceProviderDto provider = config.getServiceProvider().get(entityID);
      EPAConnectorConfigurationDto nPaConf = getnPaConfigWithCheck(provider);
      return renewMasterAndDefectList(provider, nPaConf);
    }
    catch (GovManagementException e)
    {
      return e.getManagementMessage();
    }
  }

  @Override
  public void renewMasterAndDefectList()
  {
    try
    {
      CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
      if (config == null)
      {
        return;
      }
      for ( ServiceProviderDto provider : config.getServiceProvider().values() )
      {
        EPAConnectorConfigurationDto npaConf = provider.getEpaConnectorConfiguration();
        if (npaConf != null && npaConf.isUpdateCVC())
        {
          renewMasterAndDefectList(provider, npaConf);
        }
        else if (npaConf != null)
        {
          log.debug("{}: skip renew of master and defect list for this provider, updateCVC is set to false, CVCRefID: {}",
                    provider.getEntityID(),
                    npaConf.getCVCRefID());
        }
      }
    }
    catch (Exception e)
    {
      log.error("unable to renew any master and defect list", e);
    }
  }

  private ManagementMessage renewMasterAndDefectList(ServiceProviderDto prov, EPAConnectorConfigurationDto npaConf)
  {
    try
    {
      if (!isConfigured(npaConf.getPkiConnectorConfiguration().getPassiveAuthService(), "master and defect list", prov))
      {
        return IDManagementCodes.INVALID_OPTION_FOR_PROVIDER.createMessage(prov.getEntityID(),
                                                                           "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.passiveAuthService.title");
      }
      TerminalPermission tp = facade.getTerminalPermission(npaConf.getCVCRefID());
      if (tp == null || tp.getCvc() == null)
      {
        log.error(NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE, prov.getEntityID());
        return IDManagementCodes.MISSING_TERMINAL_CERTIFICATE.createMessage(npaConf.getCVCRefID());
      }
      MasterAndDefectListHandler handler = new MasterAndDefectListHandler(npaConf, facade,
                                                                          hsmServiceHolder.getKeyStore());
      handler.updateLists();
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (GovManagementException e)
    {
      log.error("{}: unable to master and defect list: {}", prov.getEntityID(), e.getMessage(), e);
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      log.error("{}: unable to master and defect list: {}", prov.getEntityID(), e.getMessage(), e);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to master and defect list: "
                                                                     + e.getMessage());
    }
  }

  /**
   * return true if the given service is configured at least with an URL, log an info if not
   */
  private boolean isConfigured(PkiServiceType service, String dataType, ServiceProviderDto provider)
  {
    if (service != null && service.getUrl() != null && !service.getUrl().trim().isEmpty())
    {
      return true;
    }
    log.info("{}: not renewing {} because respective service not configured", provider.getEntityID(), dataType);
    return false;
  }


  @Override
  public ManagementMessage renewBlackList(String entityID)
  {
    CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
    if (config == null)
    {
      return GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage();
    }
    try
    {
      ServiceProviderDto provider = config.getServiceProvider().get(entityID);
      EPAConnectorConfigurationDto npaConf = getnPaConfigWithCheck(provider);
      ManagementMessage result = renewBlackList(provider, npaConf, false, new HashSet<>(), false);
      requestPublicSectorKeyIfNeeded(provider, npaConf);
      return result;
    }
    catch (GovManagementException e)
    {
      return e.getManagementMessage();
    }
  }

  @Override
  public void renewBlackList(boolean delta)
  {
    try
    {
      CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
      if (config == null)
      {
        return;
      }
      Set<ByteBuffer> alreadyRenewed = new HashSet<>();
      for ( ServiceProviderDto provider : config.getServiceProvider().values() )
      {
        EPAConnectorConfigurationDto npaConf = provider.getEpaConnectorConfiguration();
        if (npaConf != null && !npaConf.isUpdateCVC())
        {
          log.debug("{}: skip renew of black list for this provider, updateCVC is set to false, CVCRefID: {}",
                    provider.getEntityID(),
                    npaConf.getCVCRefID());
          continue;
        }
        renewBlackList(provider, npaConf, true, alreadyRenewed, delta);
        requestPublicSectorKeyIfNeeded(provider, npaConf);
      }
    }
    catch (Exception e)
    {
      log.error("unable to renew any blacklist", e);
    }
  }

  private ManagementMessage renewBlackList(ServiceProviderDto prov,
                                           EPAConnectorConfigurationDto npaConf,
                                           boolean all,
                                           Set<ByteBuffer> alreadyRenewed,
                                           boolean delta)
  {
    try
    {
      if (!isConfigured(npaConf.getPkiConnectorConfiguration().getRestrictedIdService(), "black list", prov))
      {
        return IDManagementCodes.INVALID_OPTION_FOR_PROVIDER.createMessage(prov.getEntityID(),
                                                                           "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.restrictedIdService.title");
      }
      TerminalPermission tp = facade.getTerminalPermission(npaConf.getCVCRefID());
      if (tp == null || tp.getCvc() == null)
      {
        log.error(NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE, prov.getEntityID());
        return IDManagementCodes.MISSING_TERMINAL_CERTIFICATE.createMessage(npaConf.getCVCRefID());
      }
      // When we already renewed the blacklist for this sector skip it now.
      if (alreadyRenewed != null && tp.getSectorID() != null
          && alreadyRenewed.contains(ByteBuffer.wrap(tp.getSectorID())))
      {
        return IDManagementCodes.DATABASE_ENTRY_EXISTS.createMessage(tp.getRefID());
      }
      RestrictedIdHandler riHandler = new RestrictedIdHandler(npaConf, facade, hsmServiceHolder.getKeyStore());
      if (alreadyRenewed != null)
      {
        if (BlackListLock.getINSTANCE().getBlackListUpdateLock().tryLock())
        {
          try
          {
            alreadyRenewed.addAll(riHandler.requestBlackList(all, delta));
          }
          finally
          {
            BlackListLock.getINSTANCE().getBlackListUpdateLock().unlock();
          }
        }
        else
        {
          log.debug("Black list is currently being updated, skipping this execution");
        }
      }

      return GlobalManagementCodes.OK.createMessage();
    }
    catch (GovManagementException e)
    {
      log.error("{}: unable to renew blacklist: {}", prov.getEntityID(), e.getMessage(), e);
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      log.error("{}: unable to renew blacklist: {}", prov.getEntityID(), e.getMessage(), e);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to renew blacklist: " + e.getMessage());
    }
  }

  /**
   * Requests a new public sector key if one is needed. This checks if the old one matches the key in the CVC and only
   * fetches the key if a new one is needed.
   *
   * @param prov
   * @param npaConf
   * @return
   */
  private ManagementMessage requestPublicSectorKeyIfNeeded(ServiceProviderDto prov,
                                                           EPAConnectorConfigurationDto npaConf)
  {
    try
    {
      if (!isConfigured(npaConf.getPkiConnectorConfiguration().getRestrictedIdService(), "black list", prov))
      {
        return IDManagementCodes.INVALID_OPTION_FOR_PROVIDER.createMessage(prov.getEntityID(),
                                                                           "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.restrictedIdService.title");
      }
      TerminalPermission tp = facade.getTerminalPermission(npaConf.getCVCRefID());
      if (tp == null || tp.getCvc() == null)
      {
        log.error(NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE, prov.getEntityID());
        return IDManagementCodes.MISSING_TERMINAL_CERTIFICATE.createMessage(npaConf.getCVCRefID());
      }

      RestrictedIdHandler riHandler = new RestrictedIdHandler(npaConf, facade, hsmServiceHolder.getKeyStore());
      riHandler.requestPublicSectorKeyIfNeeded();
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (GovManagementException e)
    {
      log.error("{}: unable to fetch public sector key: {}", prov.getEntityID(), e.getMessage(), e);
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      log.error("{}: unable to fetch public sector key: {}", prov.getEntityID(), e.getMessage(), e);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to fetch public sector key: "
                                                                     + e.getMessage());
    }
  }

  @Override
  public void renewOutdatedCVCs()
  {
    try
    {
      CoreConfigurationDto config = PoseidasConfigurator.getInstance().getCurrentConfig();
      if (config == null)
      {
        return;
      }
      assertHsmAlive();
      Map<String, Date> expirationDateMap = facade.getExpirationDates();
      if (expirationDateMap == null)
      {
        return;
      }
      List<String> lockedServiceProviders = new ArrayList<>();

      for ( ServiceProviderDto provider : config.getServiceProvider().values() )
      {
        renewCvcForProvider(provider, expirationDateMap, lockedServiceProviders);
      }
    }
    catch (Exception e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      log.error("unable to renew any CVCs", e);
    }
  }

  private void renewCvcForProvider(ServiceProviderDto provider,
                                   Map<String, Date> expirationDateMap,
                                   List<String> lockedServiceProviders)
  {
    CVCUpdateLock lock = null;
    try
    {
      String serviceProvider = provider.getEntityID();
      EPAConnectorConfigurationDto nPaConf = provider.getEpaConnectorConfiguration();
      if (nPaConf == null)
      {
        return;
      }
      if (!nPaConf.isUpdateCVC())
      {
        log.debug("{}: skip check for renew of cvc for this provider, updateCVC is set to false, CVCRefID: {}",
                  serviceProvider,
                  nPaConf.getCVCRefID());
        return;
      }
      if (!expirationDateMap.containsKey(nPaConf.getCVCRefID()))
      {
        return;
      }
      if (!isConfigured(nPaConf.getPkiConnectorConfiguration().getTerminalAuthService(),
                        "terminal certificate",
                        provider))
      {
        log.info("{}: is not configurated for certificate renewal", serviceProvider);
        return;
      }

      Calendar refreshDate = new GregorianCalendar();
      refreshDate.add(Calendar.HOUR, nPaConf.getHoursRefreshCVCBeforeExpires());
      Date expirationDate = expirationDateMap.get(nPaConf.getCVCRefID());
      if (refreshDate.getTime().before(expirationDate))
      {
        return;
      }
      TerminalPermission tp = getTerminalPermissionForRenewal(nPaConf.getCVCRefID());
      if (containsExpiredCVC(tp))
      {
        log.error("{}: Can not renew CVC because old CVC is already expired", serviceProvider);
        return;
      }

      if (lockedServiceProviders.contains(serviceProvider))
      {
        return;
      }

      lock = facade.obtainCVCUpdateLock(serviceProvider);
      if (lock == null)
      {
        log.debug("{}: Some other server is renewing CVC right now - skipping", serviceProvider);
        lockedServiceProviders.add(serviceProvider);
        return;
      }

      getCvcRequestHandler(nPaConf).makeSubsequentRequest(tp);
    }
    catch (Exception e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      log.error("{}: unable to renew CVC", provider.getEntityID(), e);
    }
    finally
    {
      if (lock != null)
      {
        facade.releaseCVCUpdateLock(lock);
      }
    }
  }

  @Override
  public ManagementMessage triggerCertRenewal(String entityID)
  {
    try
    {
      assertHsmAlive();
      EPAConnectorConfigurationDto npaConf = getnPaConfigWithCheck(entityID);

      TerminalPermission tp = getTerminalPermissionForRenewal(npaConf.getCVCRefID());
      ManagementMessage message = getCvcRequestHandler(npaConf).makeSubsequentRequest(tp, true);
      return message == null ? GlobalManagementCodes.OK.createMessage() : message;
    }
    catch (GovManagementException e)
    {
      log.error("{}: Problem while triggering a new subsequal cvc request {}", entityID, e.getManagementMessage());
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to renew CVC: " + e.getMessage());
    }
  }

  private TerminalPermission getTerminalPermissionForRenewal(String cvcRefId) throws GovManagementException
  {
    TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
    if (tp == null || tp.getCvc() == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_UNEXPECTED_ERROR, "no cvc to renew");
    }
    return tp;
  }

  private boolean containsExpiredCVC(TerminalPermission tp)
  {
    try
    {
      ECCVCertificate parsed = new ECCVCertificate(tp.getCvc());
      return parsed.getExpirationDateDate().before(new Date());
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("unable to parse given cvc", e);
    }
  }

  @Override
  public Map<String, Object> getPermissionDataInfo(String cvcRefId, boolean withBlkNumber)
  {
    Map<String, Object> result = new HashMap<>();
    try
    {
      result = InfoMapBuilder.createInfoMap(facade, cvcRefId, withBlkNumber);
    }
    catch (IllegalArgumentException e)
    {
      log.error("{}: Can not parse CVC data", cvcRefId);
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ERROR_MESSAGE,
                 new HashSet<>(Arrays.asList(IDManagementCodes.INCOMPLETE_TERMINAL_CERTIFICATE.createMessage(cvcRefId))));
    }
    return result;
  }

  @PostConstruct
  public void registerInJMX()
  {
    eidInternal.setCVCFacade(facade);
  }

  @Override
  public ManagementMessage createTerminalPermissionEntry(String cvcRefId)
  {

    if (facade.getTerminalPermission(cvcRefId) != null)
    {
      return IDManagementCodes.DATABASE_ENTRY_EXISTS.createMessage(cvcRefId);
    }

    facade.create(cvcRefId);
    return GlobalManagementCodes.OK.createMessage();
  }

  @Override
  public ManagementMessage requestFirstTerminalCertificate(String entityID,
                                                           String countryCode,
                                                           String chrMnemonic,
                                                           int sequenceNumber)
  {
    try
    {
      assertHsmAlive();
      EPAConnectorConfigurationDto epaConf = getnPaConfig(entityID);
      if (epaConf.getCVCRefID() == null || epaConf.getCVCRefID().trim().isEmpty())
      {
        return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("Please save the configuration.");
      }

      TerminalPermission terminal = facade.getTerminalPermission(epaConf.getCVCRefID());
      if (terminal == null)
      {
        createTerminalPermissionEntry(epaConf.getCVCRefID());
      }

      byte[] cvcDescription = null;

      CVCRequestHandler handler = getCvcRequestHandler(epaConf);
      handler.makeInitialRequest(cvcDescription, countryCode, chrMnemonic, sequenceNumber);
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (IllegalArgumentException e)
    {
      log.error("{}: unspecified problem", entityID, e);
      return GlobalManagementCodes.EC_INVALIDVALUE.createMessage();
    }
    catch (GovManagementException e)
    {
      log.error("{}: unspecified problem", entityID, e);
      return e.getManagementMessage();
    }
  }

  @Override
  public ManagementMessage checkReadyForFirstRequest(String entityID)
  {
    try
    {
      EPAConnectorConfigurationDto npaConf = getnPaConfigWithCheck(entityID);
      PkiConnectorConfigurationDto pkiConf = npaConf.getPkiConnectorConfiguration();
      if (pkiConf == null)
      {
        return IDManagementCodes.MISSING_OPTION_FOR_PROVIDER.createMessage("PKI connection", entityID);
      }
      checkReadyForFirstRequestPki(npaConf, pkiConf);
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (GovManagementException e)
    {
      return e.getManagementMessage();
    }
  }

  private void checkReadyForFirstRequestPki(EPAConnectorConfigurationDto npaConf, PkiConnectorConfigurationDto pkiConf)
    throws GovManagementException
  {
    BerCaPolicy policy = PolicyImplementationFactory.getInstance().getPolicy(pkiConf.getBerCaPolicyId());
    checkValuePresent(pkiConf.getBlackListTrustAnchor(), "blackListTrustAnchor");
    checkValuePresent(pkiConf.getMasterListTrustAnchor(), "masterListTrustAnchor");
    checkUrl(pkiConf.getTerminalAuthService().getUrl(), "terminalAuthService.title");
    checkUrl(pkiConf.getRestrictedIdService().getUrl(), "restrictedIdService.title");
    checkService(pkiConf, pkiConf.getTerminalAuthService(), npaConf.getCVCRefID());
    checkService(pkiConf, pkiConf.getRestrictedIdService(), npaConf.getCVCRefID());

    // d-trust does not have a passive auth service.
    if (policy.hasPassiveAuthService())
    {
      checkUrl(pkiConf.getPassiveAuthService().getUrl(), "passiveAuthService.title");
      checkService(pkiConf, pkiConf.getPassiveAuthService(), npaConf.getCVCRefID());
    }
    else
    {
      TerminalPermission tp = facade.getTerminalPermission(npaConf.getCVCRefID());
      if (tp == null || tp.getMasterList() == null || tp.getDefectList() == null)
      {
        throw new GovManagementException(IDManagementCodes.MISSING_INPUT_VALUE.createMessage("master and defetct list"));
      }
    }
    if (policy.isInitialRequestAsynchron())
    {
      checkUrl(pkiConf.getAutentURL(), "autentURL");
    }
    if (policy.isCertDescriptionFetch())
    {
      checkUrl(pkiConf.getDvcaCertDescriptionService().getUrl(), "dvcaCertDescriptionService.title");
      checkService(pkiConf, pkiConf.getDvcaCertDescriptionService(), npaConf.getCVCRefID());
    }
  }

  private void checkValuePresent(X509Certificate value, String name) throws GovManagementException
  {
    if (value == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_MISSINGCONFIGVALUE, ID_CONNECTOR_CONFIGURATION + name);
    }

  }

  private void checkUrl(String value, String fieldName) throws GovManagementException
  {
    if (value == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_MISSINGCONFIGVALUE,
                                       ID_CONNECTOR_CONFIGURATION + fieldName);
    }
    try
    {
      new URL(value);
    }
    catch (MalformedURLException e)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_INVALIDCONFIGVALUE,
                                       ID_CONNECTOR_CONFIGURATION + fieldName);
    }
  }

  private void checkService(PkiConnectorConfigurationDto pkiConf, PkiServiceType service, String entityID)
    throws GovManagementException
  {
    String sslKeysId = service.getSslKeysId();
    String filedNameSslKeysId = "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.autentService.sslKeyID";
    if (sslKeysId == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_MISSINGCONFIGVALUE, filedNameSslKeysId);
    }
    SslKeysDto keys = pkiConf.getSslKeys().get(sslKeysId);
    if (keys == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_INVALIDCONFIGVALUE, filedNameSslKeysId);
    }
    try
    {
      PKIServiceConnector.getContextLock();
      log.debug("{}: obtained lock on SSL context for connection check", entityID);
      PKIServiceConnector connector;
      if (hsmServiceHolder.getKeyStore() == null)
      {
        connector = new PKIServiceConnector(30, keys.getServerCertificate(), keys.getClientKey(),
                                            keys.getClientCertificateChain(), entityID);
      }
      else
      {
        connector = new PKIServiceConnector(30, keys.getServerCertificate(), hsmServiceHolder.getKeyStore(), null,
                                            entityID);
      }
      byte[] content = connector.getFile(service.getUrl() + "?wsdl");
      if (!new String(content).contains("wsdl"))
      {
        log.error("{}: {} does not deliver a WSDL", entityID, service.getUrl());
        throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE, service.getUrl(),
                                         "no WSDL present");
      }
    }
    catch (Exception e)
    {
      log.error("{}: no connection to {}", entityID, service.getUrl(), e);
      throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE, service.getUrl(),
                                       e.getMessage());

    }
    finally
    {
      PKIServiceConnector.releaseContextLock();
    }
  }

  private void assertHsmAlive() throws GovManagementException
  {
    List<ManagementMessage> msgs = hsmServiceHolder.warmingUp();
    if (!msgs.isEmpty())
    {
      throw new GovManagementException(msgs.get(0));
    }
  }

  @Override
  public byte[] getCvcDescription(String cvcRefId) throws GovManagementException
  {
    TerminalPermission tp = facade.getTerminalPermission(cvcRefId);
    if (tp == null)
    {
      throw new GovManagementException(IDManagementCodes.INVALID_INPUT_DATA.createMessage("cvcRefId"));
    }
    return tp.getCvcDescription();
  }

  @Override
  public ManagementMessage deletePendingCertRequest(String entityID)
  {
    try
    {
      EPAConnectorConfigurationDto nPaConf = getnPaConfigWithCheck(entityID);
      return getCvcRequestHandler(nPaConf).deletePendingRequest();
    }
    catch (GovManagementException e)
    {
      log.error("{}: Problem while deleting cvc request: {}", entityID, e.getManagementMessage());
      return e.getManagementMessage();
    }
  }

  @Override
  public boolean pingPAService(String entityID)
  {
    try
    {
      EPAConnectorConfigurationDto npaConf = getnPaConfigWithCheck(entityID);
      PkiConnectorConfigurationDto pkiConf = npaConf.getPkiConnectorConfiguration();
      checkService(pkiConf, pkiConf.getPassiveAuthService(), npaConf.getCVCRefID());
      return true;
    }
    catch (Exception e)
    {
      return false;
    }
  }

  @Override
  public boolean pingRIService(String entityID)
  {
    try
    {
      EPAConnectorConfigurationDto npaConf = getnPaConfigWithCheck(entityID);
      PkiConnectorConfigurationDto pkiConf = npaConf.getPkiConnectorConfiguration();
      checkService(pkiConf, pkiConf.getRestrictedIdService(), npaConf.getCVCRefID());
      return true;
    }
    catch (Exception e)
    {
      return false;
    }
  }
}
