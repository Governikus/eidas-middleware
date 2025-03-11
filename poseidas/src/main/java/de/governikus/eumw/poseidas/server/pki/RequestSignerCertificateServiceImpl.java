package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.BOSHSMSimulatorService;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.PKCS11HSMService;
import de.governikus.eumw.poseidas.gov2server.GovManagementException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthServiceBean;
import de.governikus.eumw.poseidas.server.pki.entities.CertInChainPK;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate.Status;
import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
@RequiredArgsConstructor
public class RequestSignerCertificateServiceImpl implements RequestSignerCertificateService
{

  private static final String LOG_MESSAGE_DEFAULT_FORMAT = "{}: {}";

  public static final String OU_REQUEST_SIGNER_CERTIFICATE = ",OU=Request Signer Certificate";

  public static final int MAXIMUM_LIFESPAN_IN_MONTHS = 36;

  private static final String EIDAS = "eIDAS";

  // See TR-3110 Part-3 A.2.1.1.
  private static final int DOMAIN_PARAMTER_ID_BRAINPOOL_P256R1 = 13;

  private final ConfigurationService configurationService;

  private final TerminalPermissionAO facade;

  private final HSMServiceHolder hsmServiceHolder;

  private final TermAuthServiceBean termAuthServiceBean;

  private final TimerHistoryService timerHistoryService;

  static String getRscChrIdAsString(Integer id)
  {
    if (id == null)
    {
      return null;
    }
    return String.format("RSC%02d", id);
  }

  private String cvcRefIdFromEntityId(String entityId)
  {
    Optional<EidasMiddlewareConfig> config = configurationService.getConfiguration();
    if (config.isEmpty())
    {
      log.debug("Cannot get cvcRefId. No configuration present");
      return null;
    }
    return config.get()
                 .getEidConfiguration()
                 .getServiceProvider()
                 .stream()
                 .filter(sp -> sp.getName().equals(entityId) || sp.getCVCRefID().equals(entityId))
                 .findFirst()
                 .orElse(new ServiceProviderType())
                 .getCVCRefID();
  }

  @Override
  public Optional<String> generateNewPendingRequestSignerCertificate(String entityId, String rscChr, int lifespan)
  {
    log.info("Generating a new RSC for service provider: {}", entityId);
    String cvcRefId = cvcRefIdFromEntityId(entityId);
    if (cvcRefId == null)
    {
      String message = "Can not generate RSC for entityID is unknown";
      log.warn(message);
      return Optional.of(message);
    }

    if (facade.getTerminalPermission(cvcRefId) == null)
    {
      facade.create(cvcRefId);
    }
    // only create new certificate if there is none pending
    if (getRequestSignerCertificate(cvcRefId, false) != null)
    {
      String message = "A pending RSC is already present, cannot create a new one";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityId, message);
      return Optional.of(message);
    }

    if (!canSetRscChrInFacade(cvcRefId, entityId, rscChr))
    {
      String message = "Cannot store RSC CHR";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityId, message);
      return Optional.of(message);
    }

    if (lifespan > MAXIMUM_LIFESPAN_IN_MONTHS)
    {
      String message = String.format("The validity period of the certificate is above the maximum allowed time of %d months. The validity period chosen is %d months.",
                                     MAXIMUM_LIFESPAN_IN_MONTHS,
                                     lifespan);
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityId, message);
      return Optional.of(message);
    }

    Integer currentRscId = facade.getCurrentRscChrId(cvcRefId);
    int nextRscId;
    if (currentRscId == null)
    {
      nextRscId = 1;
    }
    else
    {
      nextRscId = (currentRscId + 1) % 100;
    }
    String alias = buildAlias(cvcRefId, getRscChrIdAsString(nextRscId));

    HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
    ECParameterSpec ecParameterSpec = SecurityInfos.getDomainParameterMap().get(DOMAIN_PARAMTER_ID_BRAINPOOL_P256R1);
    try
    {
      KeyPair keyPair = hsm.generateKeyPair("EC", ecParameterSpec, alias, null, true, lifespan);
      saveRscInDB(cvcRefId, lifespan, hsm, keyPair, alias, nextRscId);
      String infoText = String.format("Request signer certificate with alias %s was successfully created.", alias);
      log.info(infoText);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.RSC_TRAP_NEW_PENDING_CERTIFICATE, infoText);
      return Optional.empty();
    }
    catch (Exception e)
    {
      String messageBase = "No request signer certificate was created";
      String message = String.format("%s: %s", messageBase, e.getClass().getName());
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityId, messageBase, e);
      return Optional.of(message);
    }
  }

  private boolean canSetRscChrInFacade(String cvcRefId, String entityId, String rscChr)
  {
    if (getRequestSignerCertificate(cvcRefId, true) == null)
    {
      var optionalEidasConfiguration = configurationService.getConfiguration()
                                                           .map(EidasMiddlewareConfig::getEidasConfiguration);
      if (optionalEidasConfiguration.isEmpty())
      {
        log.debug("Cannot set RSC Holder without a configuration");
        return false;
      }
      else if (entityId.equals(optionalEidasConfiguration.get().getPublicServiceProviderName())
               && Strings.isNullOrEmpty(facade.getRequestSignerCertificateHolder(cvcRefId)))
      {
        String countryCode = optionalEidasConfiguration.get().getCountryCode();
        String newHolder = countryCode + EIDAS + countryCode;
        try
        {
          facade.setRequestSignerCertificateHolder(cvcRefId, newHolder);
          return true;
        }
        catch (TerminalPermissionNotFoundException e)
        {
          if (log.isDebugEnabled())
          {
            log.debug("Failed to set rsc holder", e);
          }
          // Nothing to do here because we checked for a Terminal Permission and created one if necessary.
        }
      }
      else
      {
        if (rscChr == null || Strings.isNullOrEmpty(rscChr))
        {
          return false;
        }
        try
        {
          facade.setRequestSignerCertificateHolder(cvcRefId, rscChr);
          return true;
        }
        catch (TerminalPermissionNotFoundException e)
        {
          if (log.isDebugEnabled())
          {
            log.debug("Failed to set rsc holder", e);
          }
          // Nothing to do here because we checked for a Terminal Permission and created one if necessary.
        }
      }
    }
    return true;
  }

  private void saveRscInDB(String cvcRefId, int lifespan, HSMService hsm, KeyPair keyPair, String alias, int rscId)
    throws CertificateException
  {
    RequestSignerCertificate rsc = new RequestSignerCertificate();
    rsc.setKey(new CertInChainPK(cvcRefId, rscId));
    rsc.setStatus(Status.READY_TO_SEND);

    // Check if Request Signer Certificate should be stored in the Database
    if (hsm instanceof BOSHSMSimulatorService)
    {
      PrivateKey signer = keyPair.getPrivate();
      String fullAlias = "CN=" + alias + OU_REQUEST_SIGNER_CERTIFICATE;
      X509Certificate certificate;
      try
      {
        certificate = (X509Certificate)CertificateUtil.createSignedCert(keyPair.getPublic(),
                                                                        signer,
                                                                        fullAlias,
                                                                        fullAlias,
                                                                        lifespan,
                                                                        SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      }
      catch (CertificateException | OperatorCreationException e)
      {
        throw new CertificateException("Failed to create certificate.", e);
      }
      if (certificate == null)
      {
        log.error("Certificate is null.");
        throw new CertificateException();
      }

      rsc.setPrivateKey(keyPair.getPrivate().getEncoded());
      try
      {
        rsc.setX509RequestSignerCertificate(certificate.getEncoded());
      }
      catch (CertificateEncodingException e)
      {
        log.error("Cannot encode certificate.", e);
        throw new CertificateException(e);
      }
    }

    try
    {
      facade.setPendingRequestSignerCertificate(cvcRefId, rsc);
      log.warn("Saved pending request signer certificate {} in database. Please make sure to download and submit it to the DVCA.",
               alias);
    }
    catch (TerminalPermissionNotFoundException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Failed to set pending rsc holder", e);
      }
      // Nothing to do here because we checked for a Terminal Permission and created one if necessary.
    }
  }

  @Override
  public X509Certificate getRequestSignerCertificate(String entityId)
  {
    X509Certificate pending = getRequestSignerCertificate(entityId, false);
    if (pending == null)
    {
      return getRequestSignerCertificate(entityId, true);
    }
    return pending;
  }

  @Override
  public boolean hasRequestSignerCertificate(String entityId)
  {
    return getRequestSignerCertificate(entityId) != null;
  }

  @Override
  public X509Certificate getRequestSignerCertificate(String entityId, boolean current)
  {
    String cvcRefId = cvcRefIdFromEntityId(entityId);
    if (cvcRefId == null)
    {
      return null;
    }
    KeyStore keyStore = hsmServiceHolder.getKeyStore();
    if (keyStore == null)
    {
      return facade.getRequestSignerCertificate(cvcRefId, current);
    }
    try
    {
      Integer rscChrId = current ? facade.getCurrentRscChrId(cvcRefId) : facade.getPendingRscChrId(cvcRefId);
      if (rscChrId == null)
      {
        return null;
      }
      String alias = buildAlias(cvcRefId, getRscChrIdAsString(rscChrId));
      return (X509Certificate)keyStore.getCertificate(alias);
    }
    catch (KeyStoreException e)
    {
      log.error("Cannot load request signer certificate.", e);
    }
    return null;
  }

  private PrivateKey getRequestSignerPrivateKey(String entityId, boolean current)
  {
    String cvcRefId = cvcRefIdFromEntityId(entityId);
    if (cvcRefId == null)
    {
      return null;
    }

    KeyStore keyStore = hsmServiceHolder.getKeyStore();
    if (keyStore == null)
    {
      byte[] keyBytes = facade.getRequestSignerKey(cvcRefId, current);
      if (keyBytes != null)
      {
        try
        {
          return KeyReader.readPrivateKey(facade.getRequestSignerKey(cvcRefId, current));
        }
        catch (Exception e)
        {
          log.error("Cannot load request signer key for {}", entityId, e);
        }
      }
    }
    else
    {
      try
      {
        Integer rscChrId = current ? facade.getCurrentRscChrId(cvcRefId) : facade.getPendingRscChrId(cvcRefId);
        if (rscChrId == null)
        {
          return null;
        }
        String alias = buildAlias(cvcRefId, getRscChrIdAsString(rscChrId));
        return (PrivateKey)keyStore.getKey(alias, null);
      }
      catch (Exception e)
      {
        log.error("Cannot load request signer key for {}", entityId, e);
      }
    }
    return null;
  }

  private String buildAlias(String cvcRefID, String id)
  {
    return facade.getRequestSignerCertificateHolder(cvcRefID) + id;
  }

  @Override
  public void renewOutdated()
  {
    Optional<EidasMiddlewareConfig> config = configurationService.getConfiguration();
    List<String> succeeded = new ArrayList<>();
    List<String> noRenewalNeeded = new ArrayList<>();
    List<String> failed = new ArrayList<>();
    if (config.isEmpty())
    {
      failed.add("No eidas middleware configuration present");
      log.debug("No eidas middleware configuration present");
      return;
    }

    for ( ServiceProviderType provider : config.get().getEidConfiguration().getServiceProvider() )
    {
      if (!provider.isEnabled())
      {
        continue;
      }
      String entityId = provider.getName();
      X509Certificate current = getRequestSignerCertificate(entityId, true);
      // do not renew if there is no current
      if (current == null)
      {
        noRenewalNeeded.add(entityId);
        continue;
      }
      Calendar refreshDate = new GregorianCalendar();
      int daysRefreshRSCBeforeExpires = configurationService.getConfiguration()
                                                            .map(EidasMiddlewareConfig::getEidConfiguration)
                                                            .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                                            .map(TimerConfigurationType::getDaysRefreshRSCBeforeExpires)
                                                            .orElse(DEFAULT_DAYS_BEFORE_EXPIRATION);
      refreshDate.add(Calendar.DAY_OF_MONTH, daysRefreshRSCBeforeExpires);
      if (refreshDate.getTime().after(current.getNotAfter()))
      {
        String renewRSC = renewRSC(entityId).orElse(null);
        if (renewRSC != null)
        {
          failed.add(entityId + ": " + renewRSC);
        }
        else
        {
          succeeded.add(entityId);
        }
        facade.setAutomaticRscRenewFailed(provider.getCVCRefID(), renewRSC);
      }
      else
      {
        noRenewalNeeded.add(entityId);
      }
    }
    // if all lists are empty there should be no active service provider
    if (succeeded.isEmpty() && noRenewalNeeded.isEmpty() && failed.isEmpty())
    {
      timerHistoryService.saveTimer(TimerHistory.TimerType.BLACK_LIST_TIMER,
                                    "No active service provider found",
                                    true,
                                    true);
    }
    else
    {
      saveTimer(succeeded, noRenewalNeeded, failed);
    }
  }

  Optional<byte[]> buildCmsContainerWithPending(String entityId)
  {
    X509Certificate pendingRsc = getRequestSignerCertificate(entityId, false);
    if (pendingRsc == null)
    {
      log.error("pending RSC not found for {}", entityId);
      return Optional.empty();
    }

    try
    {
      CMSTypedData data = new CMSProcessableByteArray(new ASN1ObjectIdentifier("1.3.6.1.5.5.7"),
                                                      pendingRsc.getEncoded());
      return signCmsContainer(entityId, data, new ASN1ObjectIdentifier("0.4.0.127.0.7.3.2.4.1.1.3"));
    }
    catch (CertificateEncodingException e)
    {
      log.error("pending RSC not usable", e);
      return Optional.empty();
    }
  }

  /** {@inheritDoc} */
  @Override
  public Optional<byte[]> signCmsContainer(String entityId, CMSTypedData content, ASN1ObjectIdentifier contentType)
  {
    PrivateKey signerKey = getRequestSignerPrivateKey(entityId, true);
    X509Certificate signerCert = getRequestSignerCertificate(entityId, true);
    if (signerKey == null || signerCert == null)
    {
      log.error("current RSC not found for {}", entityId);
      return Optional.empty();
    }

    Provider provider;
    HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
    if (hsm instanceof PKCS11HSMService)
    {
      provider = hsm.getKeyStore().getProvider();
    }
    else
    {
      provider = SecurityProvider.BOUNCY_CASTLE_PROVIDER;
    }

    try
    {
      // The D-Trust DVCA needs a null parameter in the identifier
      AlgorithmIdentifier sha256WithNullIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
                                                                             DERNull.INSTANCE);
      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

      // In case of an HSM, we must use an own implementation of the ContentSigner
      ContentSigner contentSigner;
      if (hsm instanceof PKCS11HSMService)
      {
        Pkcs11ContentSignerBuilder pkcs11ContentSignerBuilder = new Pkcs11ContentSignerBuilder(provider, signerKey);
        contentSigner = pkcs11ContentSignerBuilder.build();
      }
      else
      {
        contentSigner = new JcaContentSignerBuilder("SHA256WITHPLAIN-ECDSA").setProvider(provider).build(signerKey);
      }

      DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(provider)
                                                                                                  .build();
      SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).setContentDigest(sha256WithNullIdentifier)
                                                                                                           .build(contentSigner,
                                                                                                                  signerCert);
      generator.addSignerInfoGenerator(signerInfoGenerator);
      CMSSignedData result = generator.generate(content, true);
      ContentInfo ciOrig = result.toASN1Structure();
      return Optional.of(new ContentInfo(contentType, ciOrig.getContent()).getEncoded());
    }
    catch (Exception e)
    {
      log.error("unable to sign CMS with current RSC", e);
      return Optional.empty();
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Optional<String> deletePendingRSC(String entityId)
  {
    String cvcRefId = cvcRefIdFromEntityId(entityId);
    if (cvcRefId == null)
    {
      String message = "Can not delete RSC for entityID is unknown";
      log.warn(message);
      return Optional.of(message);
    }
    KeyStore keyStore = hsmServiceHolder.getKeyStore();
    if (keyStore != null)
    {
      // Delete key from HSM
      Integer pendingRscChrId = facade.getPendingRscChrId(cvcRefId);
      String alias = buildAlias(cvcRefId, getRscChrIdAsString(pendingRscChrId));
      try
      {
        hsmServiceHolder.deleteKey(alias);
      }
      catch (IOException | HSMException e)
      {
        String message = "Can not delete pending RSC from HSM";
        log.error(LOG_MESSAGE_DEFAULT_FORMAT, entityId, message, e);
        return Optional.of(message);
      }
    }
    // Delete RSC references in Database
    try
    {
      facade.deletePendingRequestSignerCertificate(cvcRefId);
      facade.setPendingRequestSignerCertificate(cvcRefId, null);
      // If no current RSC present, then delete RSC Holder as well
      if (getRequestSignerCertificate(cvcRefId, true) == null)
      {
        facade.setRequestSignerCertificateHolder(cvcRefId, null);
      }
    }
    catch (TerminalPermissionNotFoundException e)
    {
      String message = "No Terminal Permission present";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityId, message, e);
      return Optional.of(message);
    }
    return Optional.empty();
  }

  @Override
  public Optional<String> renewRSC(String entityID)
  {
    log.info("Trying to renew request signer certificate for {}", entityID);
    String cvcRefId = cvcRefIdFromEntityId(entityID);
    if (cvcRefId == null)
    {
      String message = "Can not renew RSC for entityID is unknown";
      log.warn(message);
      return Optional.of(message);
    }

    if (getRequestSignerCertificate(entityID, true) == null)
    {
      String message = "Can not renew RSC for there is no current one";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, message);
      return Optional.of(message);
    }

    // only create new pending if there is none yet
    if (facade.getPendingRscStatus(cvcRefId) == null)
    {
      Optional<String> result = generateNewPendingRequestSignerCertificate(entityID,
                                                                           null,
                                                                           RequestSignerCertificateServiceImpl.MAXIMUM_LIFESPAN_IN_MONTHS);
      if (result.isPresent())
      {
        return result;
      }
    }
    if (facade.getPendingRscStatus(cvcRefId) == Status.READY_TO_SEND)
    {
      return sendPendingRSC(entityID);
    }
    String message = "Can not send pending request signer certificate, it was already sent with failure";
    log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, message);
    return Optional.of(message);
  }

  @Override
  public Optional<String> sendPendingRSC(String entityID)
  {
    String cvcRefId = cvcRefIdFromEntityId(entityID);
    if (cvcRefId == null)
    {
      String message = "Can not send pending RSC for entityID is unknown";
      log.warn(message);
      return Optional.of(message);
    }
    Status pendingStatus = facade.getPendingRscStatus(cvcRefId);
    if (pendingStatus == null)
    {
      String message = "Can not send pending request signer certificate, there is none";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, message);
      return Optional.of(message);
    }
    if (pendingStatus == Status.FAILURE)
    {
      String message = "Can not send pending request signer certificate, it was already sent with failure";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, message);
      return Optional.of(message);
    }

    Optional<byte[]> cmsContainerWithPending = buildCmsContainerWithPending(entityID);
    if (cmsContainerWithPending.isEmpty())
    {
      String message = "Can not create cms container";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, message);
      return Optional.of(message);
    }

    TermAuthService termAuthService;
    try
    {
      termAuthService = termAuthServiceBean.getTermAuthService(entityID);
    }
    catch (GovManagementException e)
    {
      String message = String.format("Problem while sending a pending request signer certificate: %s",
                                     e.getManagementMessage());
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, message);
      return Optional.of(message);
    }

    try
    {
      termAuthService.updateRsc(cmsContainerWithPending.get());
    }
    // bad return code
    catch (GovManagementException e)
    {
      facade.setPendingRscStatusFailed(cvcRefId);
      String message = String.format("Problem while sending a pending request signer certificate: %s",
                                     e.getManagementMessage());
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, message);
      return Optional.of(message);
    }
    // timeout or similar
    catch (RuntimeException e)
    {
      String messageBase = "Problem while sending a pending request signer certificate";
      String message = String.format("%s: %s", messageBase, e.getClass().getName());
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, entityID, messageBase, e);
      return Optional.of(message);
    }

    facade.makePendingRscToCurrentRsc(cvcRefId, true);
    log.info("Successfully renewed the request signer certificate for {}", entityID);
    return Optional.empty();
  }

  // Save timer execution results in database
  private void saveTimer(List<String> succeeded, List<String> noRenewalNeeded, List<String> failed)
  {
    StringBuilder timerExecutionMessage = new StringBuilder();
    if (!succeeded.isEmpty())
    {
      timerExecutionMessage.append("Succeeded renewals: ").append(succeeded);
    }
    if (!noRenewalNeeded.isEmpty())
    {
      if (!timerExecutionMessage.isEmpty())
      {
        timerExecutionMessage.append(System.lineSeparator());
      }
      timerExecutionMessage.append("No renewal needed for: ").append(noRenewalNeeded);
    }
    for ( String f : failed )
    {
      if (!timerExecutionMessage.isEmpty())
      {
        timerExecutionMessage.append(System.lineSeparator()).append(System.lineSeparator());
      }
      timerExecutionMessage.append(f);
    }
    timerHistoryService.saveTimer(TimerHistory.TimerType.RSC_RENEWAL,
                                  timerExecutionMessage.toString(),
                                  failed.isEmpty(),
                                  true);
  }
}
