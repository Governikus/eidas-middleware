package de.governikus.eumw.poseidas.server.timer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardserver.certrequest.CertificateRequest;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import de.governikus.eumw.poseidas.server.pki.RequestSignerCertificateService;
import de.governikus.eumw.poseidas.server.pki.TerminalPermissionAO;
import de.governikus.eumw.poseidas.server.pki.TimerHistoryService;
import de.governikus.eumw.poseidas.server.pki.entities.PendingCertificateRequest;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;
import de.governikus.eumw.poseidas.server.pki.repositories.PendingCertificateRequestRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This timer tries to send for a cvc request every 6 hours after a CVC has become invalid until it is invalid for more
 * than two days. But only if the service provider has a request signer certificate.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RequestSignerCvcRenewTimer
{

  private final RequestSignerCertificateService rscService;

  private final TerminalPermissionAO terminalPermissionAO;

  private final ConfigurationService configurationService;

  private final PendingCertificateRequestRepository pendingCertificateRequestRepository;

  private final PermissionDataHandling permissionDataHandling;

  private final TimerHistoryService timerHistoryService;

  @Value("${#{@getCvcRscRenewDelay}:120}")
  int timerRateInSeconds;

  private static X509Principal getX509Principal(X509Certificate cert)
  {
    if (cert == null)
    {
      return null;
    }
    try
    {
      return PrincipalUtil.getSubjectX509Principal(cert);
    }
    catch (CertificateEncodingException e)
    {
      return null;
    }
  }

  @Scheduled(fixedDelayString = "#{@getCvcRscRenewDelay}", initialDelay = 60, timeUnit = TimeUnit.SECONDS)
  public void checkForInvalidCVCsWithRsCertificate()
  {
    // key is terminal permission refIds
    Map<String, Date> expirationDates = terminalPermissionAO.getExpirationDates();

    if (log.isTraceEnabled())
    {
      log.trace("Checking rsc renewal with following cvc invalidation dates: {}",
                expirationDates.entrySet()
                               .stream()
                               .map(e -> String.format("\n%s - %tc", e.getKey(), e.getValue()))
                               .collect(Collectors.joining(", ")));
    }

    expirationDates.entrySet()
                   // Stream CvcRefIds and invalidation dates
                   .stream()
                   // Check if CVC is expired for less than two days
                   .filter(entry -> isCvcExpiredLessThanTwoDays(entry.getValue()))
                   // Map to CvcRefId
                   .map(Map.Entry::getKey)
                   // Check if terminal has rsc
                   .filter(rscService::hasRequestSignerCertificate)
                   // Map to service provider
                   .map(this::mapCvcRefIdToServiceProvider)
                   .filter(Optional::isPresent)
                   .map(Optional::get)
                   // Renew cvcs if not tried or last try was minimum six hors ago
                   .forEach(this::renewCvcWithRscIfLastTryWasMinimumSixHoursAgo);
  }

  static boolean isCvcExpiredLessThanTwoDays(Date invalidOn)
  {
    Duration validationDiff = Duration.between(invalidOn.toInstant(), Instant.now());
    return !validationDiff.isNegative() && validationDiff.toDays() < 2;
  }

  private void renewCvcWithRscIfLastTryWasMinimumSixHoursAgo(ServiceProviderType serviceProvider)
  {
    List<String> succeeded = new ArrayList<>();
    List<String> failed = new ArrayList<>();
    if (log.isTraceEnabled())
    {
      log.trace("Checking cvc renewal with rsc for service provider {}", serviceProvider.getName());
    }
    Optional<PendingCertificateRequest> pendingCertificateRequest = pendingCertificateRequestRepository.findById(serviceProvider.getCVCRefID());

    Date beforeSixHours = Date.from(Instant.now().minus(6, ChronoUnit.HOURS));

    // Check if last request was minimum six hors ago and return otherwise
    if (pendingCertificateRequest.isPresent() && pendingCertificateRequest.get().getLastChanged().after(beforeSixHours))
    {
      if (log.isDebugEnabled())
      {
        log.debug("Skipped cvc renewal with rsc for service provider {}, because pending requests exists and is not older than six hours.",
                  serviceProvider.getName());
      }
      failed.add(": Skipped cvc renewal with rsc for service provider %s, because pending requests exists and is not older than six hours.".formatted(serviceProvider.getName()));
      return;
    }

    // Delete pending certificate request if it is not reusable
    if (pendingCertificateRequest.isPresent() && !isPendingRequestReusable(pendingCertificateRequest.get()))
    {
      if (log.isDebugEnabled())
      {
        log.debug("Deleting pending request for service provider {}, because pending requests is not reusable.",
                  serviceProvider.getName());
      }

      pendingCertificateRequestRepository.delete(pendingCertificateRequest.get());
    }

    if (log.isDebugEnabled())
    {
      log.debug("Triggering cvc renewal for service provider {}.", serviceProvider.getName());
    }

    permissionDataHandling.triggerCertRenewal(serviceProvider.getName(), succeeded, failed);
    saveTimer(succeeded, failed);
  }


  private boolean isPendingRequestReusable(PendingCertificateRequest pendingCertificateRequest)
  {
    if (!pendingCertificateRequest.isCanBeSentAgain())
    {
      return false;
    }

    // Check if current usable pending request was signed by one of the RSCs. Otherwise, the pending request was created
    // before configuring the RSC and was signed with the invalid CVC. In that case, the pending request is not
    // reusable.

    String outerAuthorityReferenceString;
    try
    {
      CertificateRequest certificateRequest = new CertificateRequest(new ByteArrayInputStream(pendingCertificateRequest.getRequestData()));
      outerAuthorityReferenceString = certificateRequest.getOuterAuthorityReferenceString();
    }
    catch (IOException e)
    {
      if (log.isWarnEnabled())
      {
        log.warn("Could not parse pending certificate request of " + pendingCertificateRequest.getRefID(), e);
      }
      return false;
    }

    List<X509Certificate> requestSignerCertificates = new ArrayList<>();
    requestSignerCertificates.add(rscService.getRequestSignerCertificate(pendingCertificateRequest.getRefID(), true));
    requestSignerCertificates.add(rscService.getRequestSignerCertificate(pendingCertificateRequest.getRefID(), false));

    // Pending request is reusable, if it is signed by one of the RSCs.
    return requestSignerCertificates.stream()
                                    .map(RequestSignerCvcRenewTimer::getX509Principal)
                                    .filter(Objects::nonNull)
                                    .map(e -> e.getValues(X509Name.CN))
                                    .flatMap(Vector::stream)
                                    .anyMatch(e -> e.equals(outerAuthorityReferenceString));
  }

  private Optional<ServiceProviderType> mapCvcRefIdToServiceProvider(String terminalPermissionCvcRefId)
  {
    return configurationService.getConfiguration()
                               .map(EidasMiddlewareConfig::getEidConfiguration)
                               .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                               .stream()
                               .flatMap(List::stream)
                               .filter(s -> terminalPermissionCvcRefId.equals(s.getCVCRefID()))
                               .findFirst();
  }

  private void saveTimer(List<String> succeeded, List<String> failed)
  {
    StringBuilder timerExecutionMessage = new StringBuilder();
    if (!succeeded.isEmpty())
    {
      if (!timerExecutionMessage.isEmpty())
      {
        timerExecutionMessage.append(System.lineSeparator());
      }
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
    timerHistoryService.saveTimer(TimerHistory.TimerType.CVC_RENEWAL_TIMER,
                                  timerExecutionMessage.toString(),
                                  failed.isEmpty(),
                                  true);
  }
}
