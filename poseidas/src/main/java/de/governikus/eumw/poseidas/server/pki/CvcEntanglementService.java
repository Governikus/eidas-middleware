package de.governikus.eumw.poseidas.server.pki;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.springframework.stereotype.Service;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.gov2server.constants.admin.GlobalManagementCodes;
import de.governikus.eumw.poseidas.gov2server.constants.admin.ManagementMessage;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.CvcTlsCheck;
import de.governikus.eumw.poseidas.server.pki.blocklist.BlockListService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.DvcaServiceFactory;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This service allows to check if a CVC is entangled with the current TLS certificate and initiates an entanglement
 * with the DVCA as well as a CVC renewal if necessary .
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CvcEntanglementService
{

  private final CvcTlsCheck cvcTlsCheck;

  private final ConfigurationService configurationService;

  private final TerminalPermissionAO facade;

  private final DvcaServiceFactory dvcaServiceFactory;

  private final RequestSignerCertificateService requestSignerCertificateService;

  private final TimerHistoryService timerHistoryService;

  private final BlockListService blockListService;

  /**
   * Checks if the current TLS certificate is entangled with the current CVCs. An entanglement request is sent to the
   * DVCA followed by a subsequent CVC request if the entanglement needs to be renewed.
   *
   * @return A map containing the result for each service provider where the entanglement was necessary, empty map if
   *         entanglement is not possible or necessary
   */
  public Map<ServiceProviderType, ManagementMessage> checkEntanglement()
  {
    Optional<EidasMiddlewareConfig> configOptional = configurationService.getConfiguration();

    Optional<X509Certificate> optionalServerCertificate = configOptional.map(EidasMiddlewareConfig::getServerUrl)
                                                                        .flatMap(cvcTlsCheck::getOwnTlsCertificate);

    // Check TLS certificate
    if (optionalServerCertificate.map(certificate -> certificate.getNotAfter().before(new Date())).orElse(true))
    {
      timerHistoryService.saveTimer(TimerHistory.TimerType.TLS_ENTANGLE_TIMER,
                                    "No entanglement possible, because server certificate could not be found or not valid anymore",
                                    false,
                                    true);
      log.trace("No entanglement possible, because server certificate could not be found or not valid anymore");
      return Map.of();
    }

    // Get all active service providers
    List<ServiceProviderType> activeServiceProviders = getActiveServiceProviders();
    if (activeServiceProviders.isEmpty())
    {
      timerHistoryService.saveTimer(TimerHistory.TimerType.TLS_ENTANGLE_TIMER,
                                    "No active service provider found",
                                    true,
                                    true);
      return Map.of();
    }
    // Check if entanglement needs to be renewed for a service provider
    List<ServiceProviderType> spWhereEntanglementIsNecessary = getSpWhereEntanglementIsNecessary(optionalServerCertificate,
                                                                                                 activeServiceProviders);

    // Stop if renewal of the entanglement is not necessary
    if (spWhereEntanglementIsNecessary.isEmpty())
    {
      timerHistoryService.saveTimer(TimerHistory.TimerType.TLS_ENTANGLE_TIMER,
                                    "Entanglement not necessary.",
                                    true,
                                    true);
      return Map.of();
    }

    if (log.isInfoEnabled())
    {
      log.info("Entanglement of the TLS server certificate will be performed for the following service providers: {}",
               spWhereEntanglementIsNecessary.stream().map(ServiceProviderType::getName).toList());
    }

    if (log.isDebugEnabled())
    {
      log.debug("Building CMS container for new entanglement with server TLS certificate: {}",
                optionalServerCertificate.get());
    }

    // Build CMS container with new TLS certificate
    Optional<CMSProcessableByteArray> optionalCmsContainer = buildCmsContainerWithCurrentTlsCertificate(optionalServerCertificate.get());
    if (optionalCmsContainer.isEmpty())
    {
      timerHistoryService.saveTimer(TimerHistory.TimerType.TLS_ENTANGLE_TIMER,
                                    "Could not create cms container for automatic entanglement.",
                                    false,
                                    true);
      // Reason should have been already logged
      return Map.of();
    }

    // Request entanglement and renew CVC
    Map<ServiceProviderType, ManagementMessage> results = new HashMap<>();
    List<String> failed = new ArrayList<>();
    List<String> succeeded = new ArrayList<>();
    for ( ServiceProviderType serviceProviderType : spWhereEntanglementIsNecessary )
    {
      // sign CMS container with the current RSC of a service provider
      var signedCmsContainerOptional = requestSignerCertificateService.signCmsContainer(serviceProviderType.getName(),
                                                                                        optionalCmsContainer.get(),
                                                                                        new ASN1ObjectIdentifier("0.4.0.127.0.7.3.2.4.1.1.1"));
      if (signedCmsContainerOptional.isEmpty())
      {
        failed.add("%s: RSC not configured or unable to sign CMS with current RSC.".formatted(serviceProviderType.getName()));
        // Reason should have been already logged
        results.put(serviceProviderType,
                    GlobalManagementCodes.EC_INVALIDCONFIGVALUE.createMessage("RSC not configured or unable to sign CMS with current RSC"));
        continue;
      }

      if (!requestEntanglement(serviceProviderType,
                               signedCmsContainerOptional.get(),
                               optionalServerCertificate.get(),
                               results))
      {
        failed.add("%s: Could not automatically entangle new tls certificate, because the DVCA send an error".formatted(serviceProviderType.getName()));
        // Reason should have been already logged
        continue;
      }

      renewCVC(serviceProviderType, results, succeeded, failed);
    }
    saveTimer(succeeded, failed);
    return results;
  }

  private boolean requestEntanglement(ServiceProviderType serviceProviderType,
                                      byte[] signedCmsContainer,
                                      X509Certificate serverCertificate,
                                      Map<ServiceProviderType, ManagementMessage> results)
  {
    try
    {
      TermAuthService termAuthService = dvcaServiceFactory.createTermAuthService(serviceProviderType,
                                                                                 getHsmService().getKeyStore());

      // Send entanglement request
      termAuthService.sendeIDServerCerts(signedCmsContainer);

      if (log.isDebugEnabled())
      {
        log.debug("Successfully sent entanglement request to DVCA for service provider {} with certificate  {}",
                  serviceProviderType.getName(),
                  serverCertificate);
      }
      return true;
    }
    catch (GovManagementException e)
    {
      log.warn("Could not automatically entangle new TLS certificate, because the DVCA sent an error", e);
      results.put(serviceProviderType, e.getManagementMessage());
      return false;
    }

  }

  private void renewCVC(ServiceProviderType serviceProviderType,
                        Map<ServiceProviderType, ManagementMessage> results,
                        List<String> succeeded,
                        List<String> failed)
  {
    try
    {
      CVCRequestHandler cvcRequestHandler = new CVCRequestHandler(serviceProviderType, facade,
                                                                  getHsmService().getKeyStore(), configurationService,
                                                                  requestSignerCertificateService, dvcaServiceFactory,
                                                                  blockListService);


      // Send subsequent CVC request to renew the CVC
      ManagementMessage response = cvcRequestHandler.makeSubsequentRequest(facade.getTerminalPermission(serviceProviderType.getCVCRefID()));
      if (log.isDebugEnabled())
      {
        log.debug("Subsequent request for service provider {} after successful entanglement ended with following result: {} \n Details: {}",
                  serviceProviderType.getName(),
                  response.getCode().getCode(),
                  response.getDetails());
      }
      results.put(serviceProviderType, response);
      succeeded.add(serviceProviderType.getName());
    }
    catch (GovManagementException e)
    {
      failed.add("%s: Could not automatically renew CVC after successful entanglement, because we could communicate with the DVCA: %s".formatted(serviceProviderType.getName(),
                                                                                                                                                 e.getMessage()));
      log.warn("Could not automatically renew CVC after successful entanglement, because we could communicate with the DVCA",
               e);
      results.put(serviceProviderType, e.getManagementMessage());
    }
  }

  List<ServiceProviderType> getActiveServiceProviders()
  {
    Optional<EidasMiddlewareConfig> configOptional = configurationService.getConfiguration();
    return configOptional.map(EidasMiddlewareConfig::getEidConfiguration)
                         .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                         .stream()
                         .flatMap(List::stream)
                         .filter(ServiceProviderType::isEnabled)
                         .toList();
  }

  List<ServiceProviderType> getSpWhereEntanglementIsNecessary(Optional<X509Certificate> serverCertificate,
                                                              List<ServiceProviderType> activeServiceProviders)
  {
    Optional<EidasMiddlewareConfig> configOptional = configurationService.getConfiguration();
    List<ServiceProviderType> result = new ArrayList<>();
    if (configOptional.isEmpty())
    {
      return result;
    }
    for ( ServiceProviderType sp : activeServiceProviders )
    {
      CvcTlsCheck.CvcCheckResults cvcResultsForSp = cvcTlsCheck.getCvcResultsForSp(sp,
                                                                                   configOptional.get(),
                                                                                   serverCertificate);
      if (cvcResultsForSp.isCvcPresent() && !cvcResultsForSp.isCvcTlsMatch())
      {
        result.add(sp);
      }
    }
    return result;
  }

  private Optional<CMSProcessableByteArray> buildCmsContainerWithCurrentTlsCertificate(X509Certificate certificate)
  {
    try
    {
      return Optional.of(new CMSProcessableByteArray(new ASN1ObjectIdentifier("1.3.6.1.5.5.7"),
                                                     certificate.getEncoded()));
    }
    catch (CertificateEncodingException e)
    {
      log.warn("Could not create CMS container for automatic entanglement, because the current TLS certificate could not be encoded",
               e);
      return Optional.empty();
    }
  }

  private static HSMService getHsmService()
  {
    return ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
  }

  private void saveTimer(List<String> succeeded, List<String> failed)
  {
    StringBuilder timerExecutionMessage = new StringBuilder();
    if (!succeeded.isEmpty())
    {
      timerExecutionMessage.append("Succeeded: ").append(succeeded);
    }
    for ( String f : failed )
    {
      if (!timerExecutionMessage.isEmpty())
      {
        timerExecutionMessage.append(System.lineSeparator()).append(System.lineSeparator());
      }
      timerExecutionMessage.append(f);
    }

    if (log.isInfoEnabled())
    {
      log.info("TLS Entanglement finished. {}", timerExecutionMessage);
    }

    timerHistoryService.saveTimer(TimerHistory.TimerType.TLS_ENTANGLE_TIMER,
                                  timerExecutionMessage.toString(),
                                  failed.isEmpty(),
                                  true);
  }
}
