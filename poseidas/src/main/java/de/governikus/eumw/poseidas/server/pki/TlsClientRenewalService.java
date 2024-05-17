/*
 * Copyright (c) 2024 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */
package de.governikus.eumw.poseidas.server.pki;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSProcessableByteArray;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService.NoPollException;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthServiceBean;
import de.governikus.eumw.poseidas.server.pki.entities.PendingCsr;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory.TimerType;
import de.governikus.eumw.poseidas.server.pki.repositories.PendingCsrRepository;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.ConditionalCertificateSeqType;
import de.governikus.eumw.poseidas.services.terminal.auth.wsdl.v1_4_0.OptionalNoPollBeforeType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Service for TLS client certificate renewals.
 */
@RequiredArgsConstructor
@Slf4j
public abstract class TlsClientRenewalService
{

  public static final int DEFAULT_DAYS_BEFORE_EXPIRATION = 30;

  static final String LOG_MESSAGE_DEFAULT_FORMAT = "{}: {}";

  final ConfigurationService configurationService;

  private final RequestSignerCertificateService requestSignerCertificateService;

  final PendingCsrRepository pendingCsrRepository;

  private final TermAuthServiceBean termAuthServiceBean;

  private final TimerHistoryService timerHistoryService;

  final Set<String> succeeded = new HashSet<>();

  final Set<String> ongoing = new HashSet<>();

  final Set<String> failed = new HashSet<>();

  final Set<String> renewalNotNeeded = new HashSet<>();

  /**
   * Renew outdated TLS client certificates. For each SP the certificate is checked if it is due for renewal, and if so,
   * the next step in the renewal process is performed.
   */
  public void renewOutdated()
  {
    synchronized (TlsClientRenewalService.class)
    {
      log.info("Checking if TLS client certificates are due for renewal");
      succeeded.clear();
      failed.clear();
      renewalNotNeeded.clear();
      try
      {
        Optional<EidasMiddlewareConfig> configOpt = configurationService.getConfiguration();
        if (configOpt.isEmpty())
        {
          String message = "TLS client renewal not possible, no configuration present";
          log.warn(message);
          failed.add(message);
          return;
        }

        EidasMiddlewareConfig config = configOpt.get();
        Integer days = getDaysBeforeExpiration(config);
        Date deadline = Date.from(Instant.now().plus(days, ChronoUnit.DAYS));

        for ( ServiceProviderType sp : config.getEidConfiguration().getServiceProvider() )
        {
          if (!sp.isEnabled())
          {
            log.info("SP {} disabled, no TLS client cert update performed", sp.getName());
            continue;
          }

          Optional<PendingCsr> optionalPendingCsr = pendingCsrRepository.findById(sp.getName());
          // there is a pending request
          if (optionalPendingCsr.isPresent())
          {
            PendingCsr pendingCsr = optionalPendingCsr.get();
            // ...and if the time to poll has been reached, do it
            if (new Date().after(pendingCsr.getNotPollBefore()))
            {
              fetchCertificate(config, sp, pendingCsr);
            }
            else
            {
              ongoing.add(sp.getName());
            }
            continue;
          }

          checkCert(sp, deadline);
        }
      }
      finally
      {
        saveTimer();
      }
    }
  }

  /**
   * Check current TLS client certificate and perform renewal if necessary.
   *
   * @param sp service provider
   * @param deadline if certificate expires before deadline, it is renewed
   */
  abstract void checkCert(ServiceProviderType sp, Date deadline);

  /**
   * Fetch certificate for given service provider.
   *
   * @param spName name of service provider
   * @return {@link Optional#empty} in case of success, otherwise an error message
   */
  public Optional<String> fetchCertificate(String spName)
  {
    synchronized (TlsClientRenewalService.class)
    {
      Optional<EidasMiddlewareConfig> configOpt = configurationService.getConfiguration();
      if (configOpt.isEmpty())
      {
        String message = "TLS client renewal not possible, no configuration present";
        log.warn(message);
        return Optional.of(message);
      }

      EidasMiddlewareConfig config = configOpt.get();
      Optional<ServiceProviderType> spOpt = config.getEidConfiguration()
                                                  .getServiceProvider()
                                                  .stream()
                                                  .filter(sp -> spName.equals(sp.getName()))
                                                  .findFirst();
      if (spOpt.isEmpty())
      {
        String message = "TLS client renewal not possible, SP not found";
        log.warn(message);
        return Optional.of(message);
      }

      Optional<PendingCsr> optionalPendingCsr = pendingCsrRepository.findById(spName);
      if (optionalPendingCsr.isEmpty())
      {
        String message = String.format("TLS client renewal for %s not possible, no pending CSR found", spName);
        log.warn(message);
        return Optional.of(message);
      }

      PendingCsr pendingCsr = optionalPendingCsr.get();
      // ...and if the time to poll has been reached, do it
      if (new Date().before(pendingCsr.getNotPollBefore()))
      {
        String message = String.format("TLS client renewal for %s not possible, time to poll %tc not yet reached",
                                       spName,
                                       pendingCsr.getNotPollBefore());
        log.warn(message);
        return Optional.of(message);
      }
      return fetchCertificate(config, spOpt.get(), pendingCsr);
    }
  }

  private Optional<String> fetchCertificate(EidasMiddlewareConfig config, ServiceProviderType sp, PendingCsr pendingCsr)
  {
    log.info("Trying to get the new TLS client certificate for {}", sp.getName());
    ConditionalCertificateSeqType result;
    try
    {
      TermAuthService termAuthService = termAuthServiceBean.getTermAuthService(pendingCsr.getSpId());
      result = termAuthService.tryFetchNewTls(pendingCsr.getMessageId());
    }
    catch (GovManagementException e)
    {
      // bad result
      String message = String.format("Problem while fetching the new TLS certificate: %s", e.getManagementMessage());
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, sp.getName(), message);
      failed.add(sp.getName() + ": " + message);
      return Optional.of(message);
    }
    catch (NoPollException e)
    {
      String message = "CSR not yet processed, need to try again";
      // update noPollBefore
      if (e.getNoPollBefore() != null)
      {
        Date date = new Date(e.getNoPollBefore().getNoPollBefore());
        pendingCsr.setNotPollBefore(date);
        message = String.format("CSR not yet processed, need to try again after %tc", date);
      }
      pendingCsrRepository.saveAndFlush(pendingCsr);
      log.info(LOG_MESSAGE_DEFAULT_FORMAT, sp.getName(), message);
      ongoing.add(sp.getName());
      return Optional.of(message);
    }

    // delete pending
    pendingCsrRepository.delete(pendingCsr);
    Optional<String> errorMessage = storeCertificate(config, sp, result.getCertificate());
    if (errorMessage.isEmpty())
    {
      log.info("TLS client certificate successfully renewed for {}", sp.getName());
    }
    return errorMessage;
  }

  /**
   * Store a new TLS client certificate if match for request is found.
   *
   * @param config config
   * @param sp service provider
   * @param certificates received certificates
   * @return {@link Optional#empty} in case of success, otherwise an error message
   */
  abstract Optional<String> storeCertificate(EidasMiddlewareConfig config,
                                             ServiceProviderType sp,
                                             List<byte[]> certificates);

  /**
   * Search received certificates for a match with requested key.
   *
   * @param publicKey requested key
   * @param receivedCerts received certificates
   * @return matching certificate, empty if none found
   */
  static Optional<X509Certificate> matchPresentKey(PublicKey publicKey, List<byte[]> receivedCerts)
  {
    for ( byte[] certBytes : receivedCerts )
    {
      X509Certificate cert;
      try
      {
        cert = Utils.readCert(certBytes);
      }
      catch (CertificateException e)
      {
        // next
        continue;
      }
      if (publicKey.equals(cert.getPublicKey()))
      {
        return Optional.of(cert);
      }
    }
    // none found
    return Optional.empty();
  }

  /**
   * Check if a key fulfils algorithm and strength requirements.
   *
   * @param pk key
   * @return <code>true</code> if requirement fulfilled, <code>false</code> otherwise
   */
  static boolean canUseKey(PublicKey pk)
  {
    // ATTENTION this needs to be updated in case the TR-03116 changes the requirements
    switch (pk.getAlgorithm())
    {
      case "EC":
        return ((ECPublicKey)pk).getParams().getCurve().getField().getFieldSize() >= 256;
      case "RSA":
        return ((RSAPublicKey)pk).getModulus().bitLength() >= 3072;
      default:
        return false;
    }
  }

  /**
   * Sign the CMS and send it to DVCA.
   *
   * @param spName service provider name
   * @param cms CMS
   * @return {@link Optional#empty} in case of success, otherwise an error message
   */
  Optional<String> signAndSend(String spName, CMSProcessableByteArray cms)
  {
    // sign CMS
    Optional<byte[]> signedCsr = requestSignerCertificateService.signCmsContainer(spName,
                                                                                  cms,
                                                                                  new ASN1ObjectIdentifier("0.4.0.127.0.7.3.2.4.1.1.2.1"));

    if (signedCsr.isEmpty())
    {
      String message = String.format("Unable to sign CMS for SP %s", spName);
      log.warn(message);
      failed.add(spName + ": " + message);
      return Optional.of(message);
    }

    String messageId = UUID.randomUUID().toString();
    OptionalNoPollBeforeType noPollBefore;
    try
    {
      TermAuthService termAuthService = termAuthServiceBean.getTermAuthService(spName);
      noPollBefore = termAuthService.requestNewTls(signedCsr.get(), messageId);
    }
    catch (GovManagementException e)
    {
      String message = String.format("Problem while requesting the new TLS certificate: %s", e.getManagementMessage());
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, spName, message);
      failed.add(spName + ": " + message);
      return Optional.of(message);
    }
    catch (Exception e)
    {
      String message = String.format("Problem while requesting the new TLS certificate: %s", e.getMessage());
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, spName, message);
      failed.add(spName + ": " + message);
      return Optional.of(message);
    }

    PendingCsr pendingCsr = new PendingCsr(spName, messageId, noPollBefore == null ? new Date()
      : new Date(noPollBefore.getNoPollBefore() * 1000));
    pendingCsrRepository.saveAndFlush(pendingCsr);
    ongoing.add(spName);

    log.info("Successfully sent a TLS client certificate request for service provider: {}", spName);
    return Optional.empty();
  }

  /**
   * Get the "NotPollBefore" date for a given SP.
   *
   * @param spName SP name
   * @return optional date, empty if not found
   */
  public Optional<Date> getNotPollBefore(String spName)
  {
    Optional<PendingCsr> pendingCsr = pendingCsrRepository.findById(spName);
    if (pendingCsr.isEmpty())
    {
      return Optional.empty();
    }
    return Optional.of(pendingCsr.get().getNotPollBefore());
  }

  /**
   * Check if a pending CSR is present for a given SP.
   *
   * @param spName SP name
   * @return <code>true</code> if CSR present, <code>false</code> otherwise
   */
  public boolean isPendingCsrPresent(String spName)
  {
    return pendingCsrRepository.findById(spName).isPresent();
  }

  /**
   * Get the date of expiry for the current TLS client certificate of a given SP.
   *
   * @param spName SP name
   * @return date of expiry, empty if not found
   */
  public abstract Optional<Date> currentTlsCertValidUntil(String spName);

  /**
   * Delete a pending CSR for a given SP.
   *
   * @param spName SP name
   */
  public void deletePendingCsr(String spName)
  {
    pendingCsrRepository.deleteById(spName);
  }

  /**
   * Generate the DN for the subject in the CSR.
   *
   * @param spName The name of the service provider
   * @return The generated DN
   */
  protected X500Name getSubject(String spName) throws InvalidCsrException
  {
    Optional<String> countryCodeFromConfig = configurationService.getConfiguration()
                                                                 .map(EidasMiddlewareConfig::getEidasConfiguration)
                                                                 .map(EidasMiddlewareConfig.EidasConfiguration::getCountryCode);

    if (countryCodeFromConfig.isEmpty())
    {
      log.warn("The country code for the CSR is missing in the configuration.");
      throw new InvalidCsrException("The country code is missing in the configuration");
    }
    else if (!countryCodeFromConfig.get().matches("[A-Z]{2}"))
    {
      log.warn("Invalid country for the CSR code detected: '{}'", countryCodeFromConfig.get());
      throw new InvalidCsrException("Invalid country code detected: '" + countryCodeFromConfig.get() + "'");
    }
    else
    {
      String subjectDN = "CN=" + spName + " TLS client authentication, O=Governikus, C=" + countryCodeFromConfig.get();
      log.debug("The subject DN for the TLS client certificate is: {}", subjectDN);
      return new X500Name(subjectDN);
    }
  }

  /**
   * Send a CSR with given key
   *
   * @param spName name of service provider
   * @param keyName name of key
   * @return {@link Optional#empty} in case of success, otherwise an error message
   */
  public abstract Optional<String> generateAndSendCsr(String spName, String keyName);

  /**
   * Generate a new key and send CSR with it
   *
   * @param spName name of service provider
   * @return {@link Optional#empty} in case of success, otherwise an error message
   */
  public abstract Optional<String> generateAndSendCsrWithNewKey(String spName);

  private void saveTimer()
  {
    StringBuilder timerExecutionMessage = new StringBuilder();
    if (!succeeded.isEmpty())
    {
      timerExecutionMessage = appendList(succeeded, "Succeeded: ", timerExecutionMessage);
    }
    if (!ongoing.isEmpty())
    {
      timerExecutionMessage = appendList(ongoing, "Ongoing: ", timerExecutionMessage);
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
    timerHistoryService.saveTimer(TimerType.TLS_CLIENT_RENEWAL,
                                  timerExecutionMessage.toString(),
                                  failed.isEmpty(),
                                  true);
  }

  private static StringBuilder appendList(Collection<String> list, String prefix, StringBuilder stringBuilder)
  {
    if (!stringBuilder.isEmpty())
    {
      stringBuilder.append(System.lineSeparator());
    }
    return stringBuilder.append(prefix).append(list);
  }

  private static Integer getDaysBeforeExpiration(EidasMiddlewareConfig config)
  {
    TimerConfigurationType timerConfiguration = Optional.ofNullable(Optional.ofNullable(config.getEidConfiguration())
                                                                            .orElse(new EidasMiddlewareConfig.EidConfiguration())
                                                                            .getTimerConfiguration())
                                                        .orElse(new TimerConfigurationType());
    Integer days = timerConfiguration.getDaysRefreshTlsClientBeforeExpires();
    if (days == null)
    {
      days = DEFAULT_DAYS_BEFORE_EXPIRATION;
    }
    return days;
  }
}
