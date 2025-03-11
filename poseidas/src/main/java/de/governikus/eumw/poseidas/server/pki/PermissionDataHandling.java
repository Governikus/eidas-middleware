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
import java.util.Optional;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.ECCVCertificate;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.IDManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.KeyPair;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.DvcaServiceFactory;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.PKIServiceConnector;
import de.governikus.eumw.poseidas.server.pki.entities.CVCUpdateLock;
import de.governikus.eumw.poseidas.server.pki.entities.TerminalPermission;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Implementation using the EJB facade.
 */
@Component("PermissionDataHandling")
@Scope("singleton")
@RequiredArgsConstructor
@Slf4j
public class PermissionDataHandling implements PermissionDataHandlingMBean
{

  private static final String NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE = "{}: no terminal permission entry available";

  private static final String ID_CONNECTOR_CONFIGURATION = "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.";

  private static final String RENEWAL_SUCCESSFUL = "renewal_successful";

  protected final HSMServiceHolder hsmServiceHolder;

  private final TerminalPermissionAO facade;

  private final BlockListService blockListService;

  private final ConfigurationService configurationService;

  private final RequestSignerCertificateService requestSignerCertificateService;

  private final TimerHistoryService timerHistoryService;

  private final DvcaServiceFactory dvcaServiceFactory;

  private CVCRequestHandler getCvcRequestHandler(ServiceProviderType serviceProvider) throws GovManagementException
  {
    return new CVCRequestHandler(serviceProvider, facade, hsmServiceHolder.getKeyStore(), configurationService,
                                 requestSignerCertificateService, dvcaServiceFactory, blockListService);
  }

  private ServiceProviderType getServiceProvider(String entityID) throws GovManagementException
  {
    return configurationService.getConfiguration()
                               .orElseThrow(() -> new GovManagementException(GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage()))
                               .getEidConfiguration()
                               .getServiceProvider()
                               .stream()
                               .filter(sp -> sp.getName().equals(entityID))
                               .findFirst()
                               .orElseThrow(() -> new GovManagementException(IDManagementCodes.SERVICE_PROVIDER_NOT_SAVED.createMessage()));
  }

  private DvcaConfigurationType getDvcaConfigWithCheck(String entityID) throws GovManagementException
  {
    ServiceProviderType prov = getServiceProvider(entityID);
    return getDvcaConfigWithCheck(prov);
  }

  private DvcaConfigurationType getDvcaConfigWithCheck(ServiceProviderType prov) throws GovManagementException
  {
    if (prov == null)
    {
      throw new GovManagementException(IDManagementCodes.SERVICE_PROVIDER_NOT_SAVED.createMessage());
    }
    if (!prov.isEnabled())
    {
      throw new GovManagementException(IDManagementCodes.INVALID_INPUT_DATA.createMessage("service provider is not enabled "
                                                                                          + prov.getCVCRefID()));
    }
    return configurationService.getDvcaConfiguration(prov);
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
    Optional<EidasMiddlewareConfig> config = configurationService.getConfiguration();
    if (config.isEmpty())
    {
      return GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage();
    }
    try
    {
      ServiceProviderType serviceProvider = getServiceProvider(entityID);
      DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(serviceProvider);
      return renewMasterAndDefectList(serviceProvider, dvcaConfiguration);
    }
    catch (GovManagementException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to get service provider: {}", entityID, e);
      }
      return e.getManagementMessage();
    }
  }

  @Override
  public void renewMasterAndDefectList()
  {
    renewMasterAndDefectList(false);
  }

  public void renewMasterAndDefectList(boolean timerExecution)
  {
    List<String> succeeded = new ArrayList<>();
    List<String> failed = new ArrayList<>();
    try
    {
      List<ServiceProviderType> activeServiceProviders = configurationService.getConfiguration()
                                                                             .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                             .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                                                             .stream()
                                                                             .flatMap(List::stream)
                                                                             .filter(ServiceProviderType::isEnabled)
                                                                             .toList();
      if (activeServiceProviders.isEmpty())
      {
        timerHistoryService.saveTimer(TimerHistory.TimerType.GLOBAL_LIST_TIMER,
                                      "No active service provider found",
                                      true,
                                      true);
      }
      else
      {
        for ( ServiceProviderType sp : activeServiceProviders )
        {
          renewMasterAndDefectList(sp, configurationService.getDvcaConfiguration(sp), succeeded, failed);
        }
      }
    }
    catch (Exception e)
    {
      failed.add("unable to renew any master and defect list: %s".formatted(e.getMessage()));
      log.error("unable to renew any master and defect list", e);
    }

    if (timerExecution)
    {
      if (succeeded.isEmpty() && failed.isEmpty())
      {
        log.warn("Unexpected empty data for storing in timer history database.");
      }
      else
      {
        saveTimer(succeeded, failed, TimerHistory.TimerType.GLOBAL_LIST_TIMER);
      }
    }
  }

  private ManagementMessage renewMasterAndDefectList(ServiceProviderType prov, DvcaConfigurationType dvcaConfiguration)
  {
    return renewMasterAndDefectList(prov, dvcaConfiguration, new ArrayList<>(), new ArrayList<>());
  }

  private ManagementMessage renewMasterAndDefectList(ServiceProviderType prov,
                                                     DvcaConfigurationType dvcaConfiguration,
                                                     List<String> succeeded,
                                                     List<String> failed)
  {
    String provName = prov.getName();
    if (!isConfigured(dvcaConfiguration.getPassiveAuthServiceUrl(), "master and defect list", prov.getName()))
    {
      failed.add("%s: passive auth url not configured".formatted(provName));
      return IDManagementCodes.INVALID_OPTION_FOR_PROVIDER.createMessage(provName,
                                                                         "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.passiveAuthService.title");
    }
    try
    {
      TerminalPermission tp = facade.getTerminalPermission(prov.getCVCRefID());
      if (tp == null || tp.getCvc() == null)
      {
        failed.add("%s: no terminal permission entry available".formatted(provName));
        log.debug(NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE, provName);
        return IDManagementCodes.MISSING_TERMINAL_CERTIFICATE.createMessage(prov.getCVCRefID());
      }
      MasterAndDefectListHandler handler = new MasterAndDefectListHandler(prov, facade, hsmServiceHolder.getKeyStore(),
                                                                          configurationService);
      handler.updateLists();
      succeeded.add(provName);
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (MasterAndDefectListException e)
    {
      failed.add("%s: unable to renew %s: %s".formatted(provName, e.getMasterOrDefectList(), e.getMessage()));
      log.error("{}: unable to renew any master and defect list: {}", provName, e.getMessage(), e);
      return e.getManagementMessage();
    }
    catch (GovManagementException e)
    {
      failed.add("%s: unable to renew any master and defect list: %s".formatted(provName, e.getMessage()));
      log.error("{}: unable to renew any master and defect list: {}", provName, e.getMessage(), e);
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      failed.add("%s: unable to renew any master and defect list: %s".formatted(provName, e.getMessage()));
      log.error("{}: unable to renew any master and defect list: {}", provName, e.getMessage(), e);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to master and defect list: "
                                                                     + e.getMessage());
    }
  }

  /**
   * return true if the given service is configured at least with an URL, log an info if not
   */
  private boolean isConfigured(String dvcaUrl, String dataType, String providerName)
  {
    if (StringUtils.isNotBlank(dvcaUrl))
    {
      return true;
    }
    log.info("{}: not renewing {} because respective service not configured", providerName, dataType);
    return false;
  }


  @Override
  public ManagementMessage renewBlackList(String entityID)
  {
    Optional<EidasMiddlewareConfig> config = configurationService.getConfiguration();
    if (config.isEmpty())
    {
      return GlobalManagementCodes.EC_INVALIDCONFIGURATIONDATA.createMessage();
    }
    try
    {
      ServiceProviderType provider = getServiceProvider(entityID);
      DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(provider);
      ManagementMessage result = renewBlackList(provider,
                                                dvcaConfiguration,
                                                false,
                                                new HashSet<>(),
                                                false,
                                                new ArrayList<>(),
                                                new ArrayList<>());
      requestPublicSectorKeyIfNeeded(provider, dvcaConfiguration);
      return result;
    }
    catch (GovManagementException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to get service provider: {}", entityID, e);
      }
      return e.getManagementMessage();
    }
  }

  @Override
  public void renewBlackList(boolean delta)
  {
    renewBlackList(delta, false);
  }

  public void renewBlackList(boolean delta, boolean timerExecution)
  {
    List<String> succeeded = new ArrayList<>();
    List<String> failed = new ArrayList<>();
    try
    {
      Optional<EidasMiddlewareConfig> config = configurationService.getConfiguration();
      if (config.isEmpty())
      {
        failed.add("Config is empty.");
        return;
      }
      Set<ByteBuffer> alreadyRenewed = new HashSet<>();
      for ( ServiceProviderType provider : config.get().getEidConfiguration().getServiceProvider() )
      {
        if (!provider.isEnabled())
        {
          log.debug("{}: skip renew of black list for this provider, updateCVC is set to false, CVCRefID: {}",
                    provider.getName(),
                    provider.getCVCRefID());
          continue;
        }
        DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(provider);
        renewBlackList(provider, dvcaConfiguration, true, alreadyRenewed, delta, succeeded, failed);
        requestPublicSectorKeyIfNeeded(provider, dvcaConfiguration);
      }
    }
    catch (Exception e)
    {
      failed.add("unable to renew any blacklist: %s".formatted(e.getMessage()));
      log.error("unable to renew any blacklist", e);
    }

    if (timerExecution)
    {
      // if all lists are empty there should be no active service provider
      if (succeeded.isEmpty() && failed.isEmpty())
      {
        timerHistoryService.saveTimer(TimerHistory.TimerType.BLACK_LIST_TIMER,
                                      "No active service provider found",
                                      true,
                                      true);
      }
      else
      {
        saveTimer(succeeded, failed, TimerHistory.TimerType.BLACK_LIST_TIMER, delta);
      }
    }
  }

  private ManagementMessage renewBlackList(ServiceProviderType prov,
                                           DvcaConfigurationType dvcaConfiguration,
                                           boolean all,
                                           Set<ByteBuffer> alreadyRenewed,
                                           boolean delta,
                                           List<String> succeededRenewals,
                                           List<String> failedRenewals)
  {
    String providerName = prov.getName();
    if (!isConfigured(dvcaConfiguration.getRestrictedIdServiceUrl(), "black list", providerName))
    {
      failedRenewals.add("%s: restricted id service url not configured".formatted(providerName));
      return IDManagementCodes.INVALID_OPTION_FOR_PROVIDER.createMessage(providerName,
                                                                         "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.restrictedIdService.title");
    }

    try
    {
      TerminalPermission tp = facade.getTerminalPermission(prov.getCVCRefID());
      if (tp == null || tp.getCvc() == null)
      {
        failedRenewals.add("%s: no terminal permission entry available".formatted(providerName));
        log.debug(NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE, providerName);
        return IDManagementCodes.MISSING_TERMINAL_CERTIFICATE.createMessage(prov.getCVCRefID());
      }
      // When we already renewed the blacklist for this sector skip it now.
      if (alreadyRenewed != null && tp.getSectorID() != null
          && alreadyRenewed.contains(ByteBuffer.wrap(tp.getSectorID())))
      {
        succeededRenewals.add(providerName);
        return IDManagementCodes.DATABASE_ENTRY_EXISTS.createMessage(tp.getRefID());
      }
      RestrictedIdHandler riHandler = new RestrictedIdHandler(prov, facade, hsmServiceHolder.getKeyStore(),
                                                              configurationService, dvcaServiceFactory,
                                                              blockListService);
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
          failedRenewals.add("%s: Black list is currently being updated, skipping this execution.".formatted(providerName));
          log.debug("Black list is currently being updated, skipping this execution");
        }
      }
      if (alreadyRenewed.contains(ByteBuffer.wrap(tp.getSectorID())))
      {
        succeededRenewals.add(providerName);
        return GlobalManagementCodes.OK.createMessage();
      }
      failedRenewals.add(providerName);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to renew block lists");
    }
    catch (GovManagementException e)
    {
      failedRenewals.add("%s: unable to renew block lists: %s".formatted(providerName, e.getMessage()));
      log.error("{}: unable to renew block lists: {}", providerName, e.getMessage(), e);
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      failedRenewals.add("%s: unable to renew block lists: %s".formatted(providerName, e.getMessage()));
      log.error("{}: unable to renew block lists: {}", providerName, e.getMessage(), e);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to renew block lists: " + e.getMessage());
    }
  }

  private ManagementMessage requestPublicSectorKeyIfNeeded(ServiceProviderType prov,
                                                           DvcaConfigurationType dvcaConfiguration)
  {
    String providerName = prov.getName();
    try
    {
      if (!isConfigured(dvcaConfiguration.getRestrictedIdServiceUrl(), "black list", providerName))
      {
        return IDManagementCodes.INVALID_OPTION_FOR_PROVIDER.createMessage(providerName,
                                                                           "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.restrictedIdService.title");
      }
      TerminalPermission tp = facade.getTerminalPermission(prov.getCVCRefID());
      if (tp == null || tp.getCvc() == null)
      {
        log.debug(NO_TERMINAL_PERMISSION_ENTRY_AVAILABLE, providerName);
        return IDManagementCodes.MISSING_TERMINAL_CERTIFICATE.createMessage(prov.getCVCRefID());
      }

      RestrictedIdHandler riHandler = new RestrictedIdHandler(prov, facade, hsmServiceHolder.getKeyStore(),
                                                              configurationService, dvcaServiceFactory,
                                                              blockListService);
      riHandler.requestPublicSectorKeyIfNeeded();
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (GovManagementException e)
    {
      log.error("{}: unable to fetch public sector key: {}", providerName, e.getMessage(), e);
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      log.error("{}: unable to fetch public sector key: {}", providerName, e.getMessage(), e);
      return GlobalManagementCodes.EC_UNEXPECTED_ERROR.createMessage("unable to fetch public sector key: "
                                                                     + e.getMessage());
    }
  }

  @Override
  public void renewOutdatedCVCs()
  {
    List<String> succeeded = new ArrayList<>();
    List<String> failed = new ArrayList<>();
    List<String> renewalNotNeeded = new ArrayList<>();
    try
    {
      Optional<EidasMiddlewareConfig> config = configurationService.getConfiguration();
      if (config.isEmpty())
      {
        failed.add("Config is empty");
        return;
      }
      assertHsmAlive();
      Map<String, Date> expirationDateMap = facade.getExpirationDates();
      List<String> lockedServiceProviders = new ArrayList<>();
      List<ServiceProviderType> serviceProvider = config.get().getEidConfiguration().getServiceProvider();

      for ( ServiceProviderType sp : serviceProvider )
      {
        if (!sp.isEnabled())
        {
          String m = "%s: skip check for renew of cvc for this provider, updateCVC is set to false, CVCRefID: %s".formatted(sp.getName(),
                                                                                                                            sp.getCVCRefID());
          log.debug(m);
          continue;
        }
        Optional<String> message = renewCvcForProvider(sp, expirationDateMap, lockedServiceProviders);
        if (message.isEmpty())
        {
          renewalNotNeeded.add(sp.getName());
        }
        else if (RENEWAL_SUCCESSFUL.equals(message.get()))
        {
          succeeded.add(sp.getName());
        }
        else
        {
          failed.add(message.get());
        }
      }

    }
    catch (Exception e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      log.error("unable to renew any CVCs", e);
    }

    // if all lists are empty there should be no active service provider
    if (succeeded.isEmpty() && renewalNotNeeded.isEmpty() && failed.isEmpty())
    {
      timerHistoryService.saveTimer(TimerHistory.TimerType.CVC_RENEWAL_TIMER,
                                    "No active service provider found",
                                    true,
                                    true);
    }
    else
    {
      saveTimer(succeeded, failed, renewalNotNeeded, TimerHistory.TimerType.CVC_RENEWAL_TIMER, null);
    }
  }

  private Optional<String> renewCvcForProvider(ServiceProviderType provider,
                                               Map<String, Date> expirationDateMap,
                                               List<String> lockedServiceProviders)
  {
    CVCUpdateLock lock = null;
    String serviceProviderName = provider.getName();
    try
    {
      if (!expirationDateMap.containsKey(provider.getCVCRefID()))
      {
        return Optional.empty();
      }
      DvcaConfigurationType dvcaConfiguration = configurationService.getDvcaConfiguration(provider);
      if (!isConfigured(dvcaConfiguration.getTerminalAuthServiceUrl(), "terminal certificate", serviceProviderName))
      {
        String m = "%s is not configurated for certificate renewal.".formatted(serviceProviderName);
        log.info(m);
        return Optional.of(m);
      }

      Calendar refreshDate = new GregorianCalendar();
      int hoursRefreshCVCBeforeExpires = configurationService.getConfiguration()
                                                             .map(EidasMiddlewareConfig::getEidConfiguration)
                                                             .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                             .map(TimerConfigurationType::getCertRenewal)
                                                             .map(TimerTypeCertRenewal::getHoursRefreshCVCBeforeExpires)
                                                             .orElse(20);
      refreshDate.add(Calendar.HOUR, hoursRefreshCVCBeforeExpires);
      Date expirationDate = expirationDateMap.get(provider.getCVCRefID());
      if (refreshDate.getTime().before(expirationDate))
      {
        return Optional.empty();
      }
      TerminalPermission tp = getTerminalPermissionForRenewal(provider.getCVCRefID());
      if (containsExpiredCVC(tp))
      {
        String m = "%s: Can not renew CVC because old CVC is already expired".formatted(serviceProviderName);
        log.error(m);
        return Optional.of(m);
      }

      if (lockedServiceProviders.contains(serviceProviderName))
      {
        String m = "%s: Another service is currently running - skipping".formatted(serviceProviderName);
        return Optional.of(m);
      }

      lock = facade.obtainCVCUpdateLock(serviceProviderName);
      if (lock == null)
      {
        String m = "%s: Some other server is renewing CVC right now - skipping".formatted(serviceProviderName);
        log.debug(m);
        lockedServiceProviders.add(serviceProviderName);
        return Optional.of(m);
      }

      CVCRequestHandler cvcRequestHandler = getCvcRequestHandler(provider);
      ManagementMessage managementMessage = cvcRequestHandler.makeSubsequentRequest(tp);
      if (!GlobalManagementCodes.OK.equals(managementMessage.getCode()))
      {
        String m = "%s: unable to renew CVC automatically".formatted(serviceProviderName);
        log.warn(m);
        facade.setAutomaticCvcRenewFailed(provider.getCVCRefID(), true);
        return Optional.of(m);
      }
      return Optional.of(RENEWAL_SUCCESSFUL);
    }
    catch (Exception e)
    {
      String m = "%s: unable to renew CVC".formatted(serviceProviderName);
      facade.setAutomaticCvcRenewFailed(provider.getCVCRefID(), true);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      log.error("{}: unable to renew CVC", serviceProviderName, e);
      return Optional.of(m);
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
    return triggerCertRenewal(entityID, new ArrayList<>(), new ArrayList<>());
  }

  public ManagementMessage triggerCertRenewal(String entityID, List<String> succeeded, List<String> failed)
  {
    try
    {
      assertHsmAlive();
      ServiceProviderType serviceProvider = getServiceProvider(entityID);

      TerminalPermission tp = getTerminalPermissionForRenewal(serviceProvider.getCVCRefID());
      ManagementMessage message = getCvcRequestHandler(serviceProvider).makeSubsequentRequest(tp);
      if (message == null)
      {
        succeeded.add(entityID);
      }
      else
      {
        failed.add("%s: %s".formatted(entityID, message));
      }
      return message == null ? GlobalManagementCodes.OK.createMessage() : message;
    }
    catch (GovManagementException e)
    {
      log.error("{}: Problem while triggering a new subsequal cvc request {}", entityID, e.getManagementMessage());
      failed.add("%s: Problem while triggering a new subsequal cvc request: %s".formatted(entityID,
                                                                                          e.getManagementMessage()));
      return e.getManagementMessage();
    }
    catch (Exception e)
    {
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.CVC_TRAP_LAST_RENEWAL_STATUS, 1);
      log.debug("unable to renew CVC", e);
      failed.add("%s: unable to renew CVC: %s".formatted(entityID, e.getMessage()));
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
      result = InfoMapBuilder.createInfoMap(facade, blockListService, cvcRefId, withBlkNumber);
    }
    catch (IllegalArgumentException e)
    {
      log.error("{}: Can not parse CVC data", cvcRefId);
      result.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ERROR_MESSAGE,
                 new HashSet<>(Arrays.asList(IDManagementCodes.INCOMPLETE_TERMINAL_CERTIFICATE.createMessage(cvcRefId))));
    }
    return result;
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
      ServiceProviderType epaConf = getServiceProvider(entityID);
      if (StringUtils.isBlank(epaConf.getCVCRefID()))
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
      ServiceProviderType serviceProvider = getServiceProvider(entityID);
      DvcaConfigurationType dvcaConfiguration = getDvcaConfigWithCheck(serviceProvider);
      checkReadyForFirstRequestPki(dvcaConfiguration, serviceProvider);
      return GlobalManagementCodes.OK.createMessage();
    }
    catch (GovManagementException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Check readiness for first request for service provider {}", entityID, e);
      }
      return e.getManagementMessage();
    }
  }

  private void checkReadyForFirstRequestPki(DvcaConfigurationType dvcaConfigurationType,
                                            ServiceProviderType serviceProvider)
    throws GovManagementException
  {

    checkValuePresent(configurationService.getCertificate(dvcaConfigurationType.getBlackListTrustAnchorCertificateName()),
                      "blackListTrustAnchor");
    checkValuePresent(configurationService.getCertificate(dvcaConfigurationType.getMasterListTrustAnchorCertificateName()),
                      "masterListTrustAnchor");
    checkUrl(dvcaConfigurationType.getTerminalAuthServiceUrl(), "terminalAuthService.title");
    checkUrl(dvcaConfigurationType.getRestrictedIdServiceUrl(), "restrictedIdService.title");
    checkService(dvcaConfigurationType, serviceProvider, dvcaConfigurationType.getTerminalAuthServiceUrl());
    checkService(dvcaConfigurationType, serviceProvider, dvcaConfigurationType.getRestrictedIdServiceUrl());
    checkUrl(dvcaConfigurationType.getPassiveAuthServiceUrl(), "passiveAuthService.title");
    checkService(dvcaConfigurationType, serviceProvider, dvcaConfigurationType.getPassiveAuthServiceUrl());
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

  private void checkService(DvcaConfigurationType dvcaConfiguration, ServiceProviderType serviceProvider, String pkiUrl)
    throws GovManagementException
  {
    X509Certificate dvcaServerCertificate = configurationService.getCertificate(dvcaConfiguration.getServerSSLCertificateName());
    KeyPair clientKeyPair = serviceProvider.getClientKeyPairName() == null ? null
      : configurationService.getKeyPair(serviceProvider.getClientKeyPairName());
    String filedNameSslKeysId = "ID.jsp.serviceProvider.nPaPkiConnectorConfiguration.autentService.sslKeyID";

    if (dvcaServerCertificate == null || clientKeyPair == null && hsmServiceHolder.getKeyStore() == null)
    {
      throw new GovManagementException(GlobalManagementCodes.EC_INVALIDCONFIGVALUE, filedNameSslKeysId);
    }
    String serviceProviderName = serviceProvider.getName();
    try
    {
      PKIServiceConnector.getContextLock();
      log.debug("{}: obtained lock on SSL context for connection check", serviceProviderName);
      PKIServiceConnector connector;
      if (hsmServiceHolder.getKeyStore() == null)
      {
        List<X509Certificate> clientCertificate = List.of(clientKeyPair.getCertificate());
        connector = new PKIServiceConnector(30, dvcaServerCertificate, clientKeyPair.getKey(), clientCertificate,
                                            serviceProviderName);
      }
      else
      {
        connector = new PKIServiceConnector(30, dvcaServerCertificate, hsmServiceHolder.getKeyStore(), null,
                                            serviceProvider.getCVCRefID());
      }
      byte[] content = connector.getFile(pkiUrl + "?wsdl");
      if (!new String(content).contains("wsdl"))
      {
        log.error("{}: {} does not deliver a WSDL", serviceProviderName, pkiUrl);
        throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE, pkiUrl,
                                         "no WSDL present");
      }
    }
    catch (Exception e)
    {
      log.error("{}: no connection to {}", serviceProviderName, pkiUrl, e);
      throw new GovManagementException(GlobalManagementCodes.EXTERNAL_SERVICE_NOT_REACHABLE, pkiUrl, e.getMessage());

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
  public boolean pingPAService(String entityID)
  {
    try
    {
      DvcaConfigurationType dvcaConfiguration = getDvcaConfigWithCheck(entityID);
      ServiceProviderType serviceProvider = getServiceProvider(entityID);
      checkService(dvcaConfiguration, serviceProvider, dvcaConfiguration.getPassiveAuthServiceUrl());
      return true;
    }
    catch (Exception e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to ping pa service for service provider {}", entityID, e);
      }
      return false;
    }
  }

  @Override
  public boolean pingRIService(String entityID)
  {
    try
    {
      DvcaConfigurationType dvcaConfiguration = getDvcaConfigWithCheck(entityID);
      ServiceProviderType serviceProvider = getServiceProvider(entityID);
      checkService(dvcaConfiguration, serviceProvider, dvcaConfiguration.getRestrictedIdServiceUrl());
      return true;
    }
    catch (Exception e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to ping ri service for service provider {}", entityID, e);
      }
      return false;
    }
  }

  private void saveTimer(List<String> succeeded, List<String> failed, TimerHistory.TimerType timerType)
  {
    saveTimer(succeeded, failed, new ArrayList<>(), timerType, null);
  }

  private void saveTimer(List<String> succeeded, List<String> failed, TimerHistory.TimerType timerType, Boolean delta)
  {
    saveTimer(succeeded, failed, new ArrayList<>(), timerType, delta);
  }

  // Save timer execution results in database
  private void saveTimer(List<String> succeeded,
                         List<String> failed,
                         List<String> renewalNotNeeded,
                         TimerHistory.TimerType timerType,
                         Boolean delta)
  {
    StringBuilder timerExecutionMessage = new StringBuilder();
    if (null != delta)
    {
      timerExecutionMessage.append("Delta: ").append(delta);
    }

    if (!succeeded.isEmpty())
    {
      timerExecutionMessage = appendList(succeeded, "Succeeded: ", timerExecutionMessage);
    }


    if (!renewalNotNeeded.isEmpty())
    {
      timerExecutionMessage = appendList(renewalNotNeeded, "No renewals needed: ", timerExecutionMessage);
    }

    for ( String f : failed )
    {
      if (!timerExecutionMessage.isEmpty())
      {
        timerExecutionMessage.append(System.lineSeparator()).append(System.lineSeparator());
      }
      timerExecutionMessage.append(f);
    }
    timerHistoryService.saveTimer(timerType, timerExecutionMessage.toString(), failed.isEmpty(), true);
  }

  private StringBuilder appendList(List<String> list, String prefix, StringBuilder stringBuilder)
  {
    if (!stringBuilder.isEmpty())
    {
      stringBuilder.append(System.lineSeparator());
    }
    return stringBuilder.append(prefix).append(list);
  }

}
