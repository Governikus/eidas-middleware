package de.governikus.eumw.poseidas.server.pki;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.SecurityInfos;
import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.BOSHSMSimulatorService;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.monitoring.SNMPConstants;
import de.governikus.eumw.poseidas.server.monitoring.SNMPTrapSender;
import lombok.RequiredArgsConstructor;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
@RequiredArgsConstructor
public class RequestSignerCertificateServiceImpl implements RequestSignerCertificateService
{

  public static final String OU_REQUEST_SIGNER_CERTIFICATE = ",OU=Request Signer Certificate";

  public static final int MAXIMUM_LIFESPAN_IN_MONTHS = 36;

  private static final String EIDAS = "eIDAS";

  // See TR-3110 Part-3 A.2.1.1.
  private static final int DOMAIN_PARAMTER_ID_BRAINPOOL_P256R1 = 13;

  private final ConfigurationService configurationService;

  private final TerminalPermissionAO facade;

  private final HSMServiceHolder hsmServiceHolder;

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
                 .filter(sp -> sp.getName().equals(entityId))
                 .findFirst()
                 .orElse(new ServiceProviderType())
                 .getCVCRefID();
  }

  @Override
  public boolean generateNewPendingRequestSignerCertificate(String entityId, String rscChr, int lifespan)
  {
    String cvcRefId = cvcRefIdFromEntityId(entityId);
    if (facade.getTerminalPermission(cvcRefId) == null)
    {
      facade.create(cvcRefId);
    }
    // only create new certificate if there is none pending
    if (facade.getRequestSignerCertificate(cvcRefId, false) != null)
    {
      return false;
    }

    if (!canSetRscChrInFacade(cvcRefId, entityId, rscChr))
    {
      return false;
    }

    if (lifespan > MAXIMUM_LIFESPAN_IN_MONTHS)
    {
      log.error("The validity period of the certificate is above the maximum allowed time of {} months. The validity period chosen is {} months.",
                MAXIMUM_LIFESPAN_IN_MONTHS,
                lifespan);
      return false;
    }

    Integer currentRscId = facade.getCurrentRscChrId(cvcRefId);
    int nextRscId;
    String issuerAlias;
    if (currentRscId == null)
    {
      nextRscId = 1;
      issuerAlias = null;
    }
    else
    {
      nextRscId = (currentRscId + 1) % 100;
      Calendar cal = new GregorianCalendar();
      cal.add(Calendar.MINUTE, 1);
      try
      {
        X509Certificate currentRequestSigner = getRequestSignerCertificate(cvcRefId, true);
        currentRequestSigner.checkValidity();
        // this assumes the system is fast enough to perform the signature in the next minute
        currentRequestSigner.checkValidity(cal.getTime());
        issuerAlias = buildAlias(cvcRefId, getRscChrIdAsString(currentRscId));
      }
      catch (NullPointerException | CertificateExpiredException | CertificateNotYetValidException e)
      {
        // if current is not present or invalid, do self-sign
        issuerAlias = null;
      }
    }
    String alias = buildAlias(cvcRefId, getRscChrIdAsString(nextRscId));

    HSMService hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
    ECParameterSpec ecParameterSpec = SecurityInfos.getDomainParameterMap().get(DOMAIN_PARAMTER_ID_BRAINPOOL_P256R1);
    try
    {
      KeyPair keyPair = hsm.generateKeyPair("EC", ecParameterSpec, alias, issuerAlias, true, lifespan);
      saveRscInDB(cvcRefId, lifespan, hsm, keyPair, alias, issuerAlias, nextRscId);
      String infoText = String.format("Request signer certificate with alias %s was successfully created.", alias);
      log.info(infoText);
      SNMPTrapSender.sendSNMPTrap(SNMPConstants.TrapOID.RSC_TRAP_NEW_PENDING_CERTIFICATE, infoText);
      return true;
    }
    catch (Exception e)
    {
      log.error("No request signer certificate was created.", e);
      return false;
    }
  }

  private boolean canSetRscChrInFacade(String cvcRefId, String entityId, String rscChr)
  {
    if (Strings.isNullOrEmpty(facade.getRequestSignerCertificateHolder(cvcRefId)))
    {
      var optionalEidasConfiguration = configurationService.getConfiguration()
                                                           .map(EidasMiddlewareConfig::getEidasConfiguration);
      if (optionalEidasConfiguration.isEmpty())
      {
        log.debug("Cannot set RSC Holder without a configuration");
        return false;
      }
      else if (entityId.equals(optionalEidasConfiguration.get().getPublicServiceProviderName()))
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
          // Nothing to do here because we checked for a Terminal Permission and created one if necessary.
        }
      }
    }
    return true;
  }

  private void saveRscInDB(String cvcRefId,
                           int lifespan,
                           HSMService hsm,
                           KeyPair keyPair,
                           String alias,
                           String issuerAlias,
                           int rscId)
    throws CertificateException
  {
    RequestSignerCertificate rsc = new RequestSignerCertificate();
    rsc.setKey(new CertInChainPK(cvcRefId, rscId));

    // Check if Request Signer Certificate should be stored in the Database
    if (hsm instanceof BOSHSMSimulatorService)
    {
      PrivateKey signer = keyPair.getPrivate();
      String fullIssuerAlias = "CN=" + alias;
      if (issuerAlias != null)
      {
        byte[] issuerKey = facade.getRequestSignerKey(cvcRefId, true);
        try
        {
          signer = BOSHSMSimulatorService.buildPrivateKey(issuerKey);
          fullIssuerAlias = "CN=" + issuerAlias;
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
          // self sign instead
        }
      }
      X509Certificate certificate = (X509Certificate)CertificateUtil.createSignedCert(keyPair.getPublic(),
                                                                                      signer,
                                                                                      "CN=" + alias
                                                                                              + OU_REQUEST_SIGNER_CERTIFICATE,
                                                                                      fullIssuerAlias + OU_REQUEST_SIGNER_CERTIFICATE,
                                                                                      lifespan,
                                                                                      SecurityProvider.BOUNCY_CASTLE_PROVIDER);
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

  private String buildAlias(String cvcRefID, String id)
  {
    return facade.getRequestSignerCertificateHolder(cvcRefID) + id;
  }

  @Override
  public void renewOutdated()
  {
    Optional<EidasMiddlewareConfig> config = configurationService.getConfiguration();
    if (config.isEmpty())
    {
      log.debug("No eidas middleware configuration present");
      return;
    }
    for ( ServiceProviderType provider : config.get().getEidConfiguration().getServiceProvider() )
    {
      if (!provider.isEnabled())
      {
        continue;
      }
      String refID = provider.getCVCRefID();
      X509Certificate current = getRequestSignerCertificate(refID, true);
      // do not renew if there is no current
      if (current == null)
      {
        continue;
      }
      Calendar refreshDate = new GregorianCalendar();
      refreshDate.add(Calendar.DAY_OF_MONTH, 56);
      if (refreshDate.getTime().after(current.getNotAfter()))
      {
        log.info("Trying to renew request signer certificate for {}", provider.getName());
        generateNewPendingRequestSignerCertificate(refID, null, MAXIMUM_LIFESPAN_IN_MONTHS);
      }
    }
  }
}
