package de.governikus.eumw.poseidas.server.pki;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.cardserver.service.ServiceRegistry;
import de.governikus.eumw.poseidas.cardserver.service.hsm.HSMServiceFactory;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMException;
import de.governikus.eumw.poseidas.cardserver.service.hsm.impl.HSMService;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthServiceBean;
import de.governikus.eumw.poseidas.server.pki.repositories.PendingCsrRepository;
import lombok.extern.slf4j.Slf4j;



/**
 * Service for TLS client certificate renewals used when keys are in HSM.
 */
@Service
@ConditionalOnProperty(name = "hsm.type", havingValue = "PKCS11")
@Slf4j
public class TlsClientRenewalHsmService extends TlsClientRenewalService
{

  private static final String HSM_PENDING_SUFFIX = "-PendingTLS";

  private HSMService hsm;

  public TlsClientRenewalHsmService(ConfigurationService configurationService,
                                    RequestSignerCertificateService requestSignerCertificateService,
                                    PendingCsrRepository pendingCsrRepository,
                                    TermAuthServiceBean termAuthServiceBean,
                                    TimerHistoryService timerHistoryService)
  {
    super(configurationService, requestSignerCertificateService, pendingCsrRepository, termAuthServiceBean,
          timerHistoryService);
  }

  private void init()
  {
    if (hsm == null)
    {
      hsm = ServiceRegistry.Util.getServiceRegistry().getService(HSMServiceFactory.class).getHSMService();
    }
  }

  @Override
  Optional<String> storeCertificate(EidasMiddlewareConfig config, ServiceProviderType sp, List<byte[]> certificates)
  {
    init();
    String defaultName = sp.getCVCRefID();
    String pendingName = defaultName + HSM_PENDING_SUFFIX;
    KeyStore hsmStore = hsm.getKeyStore();
    try
    {
      String usedName = hsm.containsKey(pendingName) ? pendingName : defaultName;

      // check key in received cert
      Optional<X509Certificate> foundCert = matchPresentKey(hsm.getPublicKey(usedName), certificates);
      if (foundCert.isEmpty())
      {
        String message = "Received TLS certificate does not match requested key";
        log.warn(LOG_MESSAGE_DEFAULT_FORMAT, sp.getName(), message);
        failed.add(sp.getName() + ": " + message);
        return Optional.of(message);
      }
      if (usedName.equals(pendingName))
      {
        hsmStore.deleteEntry(defaultName);
      }
      hsmStore.setKeyEntry(defaultName, hsmStore.getKey(usedName, null), null, new Certificate[]{foundCert.get()});
      succeeded.add(sp.getName());
      return Optional.empty();
    }
    catch (Exception e)
    {
      String message = "Unable to store new certificate";
      log.warn(LOG_MESSAGE_DEFAULT_FORMAT, sp.getName(), message);
      failed.add(sp.getName() + ": " + message);
      return Optional.of(message);
    }
    finally
    {
      try
      {
        hsmStore.deleteEntry(pendingName);
      }
      catch (KeyStoreException e)
      {
        log.warn(LOG_MESSAGE_DEFAULT_FORMAT, sp.getName(), "Unable to delete pending certificate");
      }
    }
  }

  @Override
  void checkCert(ServiceProviderType sp, Date deadline)
  {
    init();
    String defaultName = sp.getCVCRefID();
    X509Certificate cert;
    try
    {
      cert = (X509Certificate)hsm.getKeyStore().getCertificate(defaultName);
    }
    catch (KeyStoreException e)
    {
      log.info("SP {} has no TLS client certificate, no update performed", sp.getName());
      renewalNotNeeded.add(sp.getName());
      return;
    }

    // not found
    if (cert == null)
    {
      log.info("SP {} has no TLS client certificate, no update performed", sp.getName());
      renewalNotNeeded.add(sp.getName());
      return;
    }

    // check expiration date
    if (cert.getNotAfter().after(deadline))
    {
      log.info("Validity period of TLS client certificate of SP {} still long enough, no update performed",
               sp.getName());
      renewalNotNeeded.add(sp.getName());
      return;
    }

    String keyNameToUse = defaultName + HSM_PENDING_SUFFIX;

    try
    {
      if (hsm.containsKey(keyNameToUse))
      {
        log.info("HSM contains already a key with name {}", keyNameToUse);
        PublicKey keyToUse = hsm.getPublicKey(keyNameToUse);
        if (canUseKeyAlg(keyToUse) && canUseKeySize(keyToUse))
        {
          generateAndSendCsrUnchecked(sp.getName(), keyNameToUse);
          return;
        }
        String message = String.format("Key with name %s can not be used for TLS client key renewal. Please delete the "
                                       + "key and create a new %s key with at least %d bits, or allow the eIDAS middleware"
                                       + " to generate a new key.",
                                       keyNameToUse,
                                       KEY_ALGO,
                                       MINIMAL_KEY_SIZE_RSA);
        log.warn(message);
        failed.add(sp.getName() + ": " + message);
        return;
      }

      // key not yet in HSM
      log.info("Generating new key with name {} for the renewal of mTLS key for the communication with the DVCA.",
               keyNameToUse);
      generateAndStoreKeyPair(keyNameToUse);
    }
    catch (Exception e)
    {
      String message = String.format("Unable to find TLS client key for SP %s", sp.getName());
      log.warn(message, e);
      failed.add(sp.getName() + ": " + message);
      return;
    }
    generateAndSendCsrUnchecked(sp.getName(), keyNameToUse);
  }

  private Optional<String> generateAndSendCsrUnchecked(String spName, String keyNameToUse)
  {
    // generate CSR and put into CMS
    CMSProcessableByteArray cms;
    try
    {
      PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(getSubject(spName),
                                                                                                 hsm.getPublicKey(keyNameToUse));
      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(CertificateUtil.getAlgorithm(hsm.getPublicKey(keyNameToUse)));
      ContentSigner contentSigner = contentSignerBuilder.build((PrivateKey)hsm.getKeyStore()
                                                                              .getKey(keyNameToUse, null));
      PKCS10CertificationRequest csr = pkcs10Builder.build(contentSigner);
      cms = new CMSProcessableByteArray(new ASN1ObjectIdentifier("1.2.840.113549.1.10"), csr.getEncoded());
    }
    catch (IOException | OperatorCreationException | KeyStoreException | UnrecoverableKeyException
      | NoSuchAlgorithmException | HSMException | InvalidCsrException e)
    {
      String message = String.format("Unable to generate CSR for SP %s", spName);
      log.warn(message, e);
      failed.add(spName + ": " + message);
      return Optional.of(message);
    }

    return signAndSend(spName, cms);
  }

  private void generateAndStoreKeyPair(String keyName) throws NoSuchAlgorithmException, NoSuchProviderException,
    InvalidAlgorithmParameterException, IOException, HSMException, CertificateException
  {
    // RSA 4096 bits
    RSAKeyGenParameterSpec rsaKeyGenParameterSpec = new RSAKeyGenParameterSpec(DEFAULT_KEY_SIZE_RSA,
                                                                               RSAKeyGenParameterSpec.F4);
    hsm.generateKeyPair(KEY_ALGO, rsaKeyGenParameterSpec, keyName, null, true, 360);
  }

  @Override
  public Optional<String> generateAndSendCsr(String spName, String keyName)
  {
    synchronized (TlsClientRenewalService.class)
    {
      log.info("Renewing the TLS client certificate with keypair '{}' for service provider: {}", keyName, spName);

      init();

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

      String pendingName = spOpt.get().getCVCRefID() + HSM_PENDING_SUFFIX;
      try
      {
        if (!hsm.containsKey(pendingName))
        {
          String message = "TLS client renewal not possible, no key present with name '%s'".formatted(pendingName);
          log.warn(message);
          return Optional.of(message);
        }
        PublicKey pubKey = hsm.getPublicKey(pendingName);
        if (!canUseKeyAlg(pubKey))
        {
          String message = "TLS client renewal not possible, key algorithm for key '%s' not supported. Currently only %s keys with at least %d bits supported.".formatted(pendingName,
                                                                                                                                                                          KEY_ALGO,
                                                                                                                                                                          MINIMAL_KEY_SIZE_RSA);
          log.warn(message);
          return Optional.of(message);
        }
        if (!canUseKeySize(pubKey))
        {
          String message = "TLS client renewal not possible, key strength for key '%s' not sufficient. Currently only %s keys with at least %d bits supported".formatted(pendingName,
                                                                                                                                                                         KEY_ALGO,
                                                                                                                                                                         MINIMAL_KEY_SIZE_RSA);
          log.warn(message);
          return Optional.of(message);
        }
      }
      catch (Exception e)
      {
        String message = "TLS client renewal not possible, HSM error";
        log.warn(message, e);
        return Optional.of(message);
      }
      return generateAndSendCsrUnchecked(spName, pendingName);
    }
  }

  @Override
  public Optional<String> generateAndSendCsrWithNewKey(String spName)
  {
    synchronized (TlsClientRenewalService.class)
    {
      log.info("Renewing the TLS client certificate with a newly generated key for service provider: {}", spName);

      init();

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

      String pendingName = spOpt.get().getCVCRefID() + HSM_PENDING_SUFFIX;
      try
      {
        if (hsm.containsKey(pendingName))
        {
          log.info("There is already a pending key for SP {}. It will be replaced by a new one.", spName);
        }
        generateAndStoreKeyPair(pendingName);
      }
      catch (Exception e)
      {
        String message = "TLS client renewal not possible, HSM error";
        log.warn(message, e);
        return Optional.of(message);
      }
      return generateAndSendCsrUnchecked(spName, pendingName);
    }
  }

  @Override
  public Optional<Date> currentTlsCertValidUntil(String spName)
  {
    init();
    Optional<EidasMiddlewareConfig> configOpt = configurationService.getConfiguration();
    if (configOpt.isEmpty())
    {
      return Optional.empty();
    }
    Optional<ServiceProviderType> spOpt = configOpt.get()
                                                   .getEidConfiguration()
                                                   .getServiceProvider()
                                                   .stream()
                                                   .filter(sp -> spName.equals(sp.getName()))
                                                   .findFirst();
    if (spOpt.isEmpty())
    {
      return Optional.empty();
    }

    try
    {
      X509Certificate cert = (X509Certificate)hsm.getKeyStore().getCertificate(spOpt.get().getCVCRefID());
      if (cert == null)
      {
        return Optional.empty();
      }
      return Optional.of(cert.getNotAfter());
    }
    catch (KeyStoreException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Unable to get certificate for serviceprovider {} ", spName, e);
      }
      return Optional.empty();
    }
  }

  // Only for tests
  void setHsm(HSMService hsm)
  {
    this.hsm = hsm;
  }
}
