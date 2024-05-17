package de.governikus.eumw.poseidas.server.pki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

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
import de.governikus.eumw.config.EidasMiddlewareConfig.EidConfiguration;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.cardserver.CertificateUtil;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationException;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.idprovider.config.KeyPair;
import de.governikus.eumw.poseidas.server.pki.caserviceaccess.TermAuthServiceBean;
import de.governikus.eumw.poseidas.server.pki.repositories.PendingCsrRepository;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.extern.slf4j.Slf4j;


/**
 * Service for TLS client certificate renewals used when keys are in DB.
 */
@Service
@ConditionalOnProperty(name = "hsm.type", havingValue = "NO_HSM", matchIfMissing = true)
@Slf4j
public class TlsClientRenewalDbService extends TlsClientRenewalService
{

  public TlsClientRenewalDbService(ConfigurationService configurationService,
                                   RequestSignerCertificateService requestSignerCertificateService,
                                   PendingCsrRepository pendingCsrRepository,
                                   TermAuthServiceBean termAuthServiceBean,
                                   TimerHistoryService timerHistoryService)
  {
    super(configurationService, requestSignerCertificateService, pendingCsrRepository, termAuthServiceBean,
          timerHistoryService);
  }

  @Override
  Optional<String> storeCertificate(EidasMiddlewareConfig config, ServiceProviderType sp, List<byte[]> certificates)
  {
    // determine key pair to use
    String keyPairName = sp.getPendingClientKeyPairName() == null ? sp.getClientKeyPairName()
      : sp.getPendingClientKeyPairName();

    KeyPair keyPair;
    try
    {
      keyPair = configurationService.getKeyPair(keyPairName);
    }
    catch (ConfigurationException e)
    {
      String message = "Key pair not found";
      log.warn(message, e);
      failed.add(sp.getName() + ": " + message);
      return Optional.of(message);
    }

    // check key in received cert
    Optional<X509Certificate> foundCert = matchPresentKey(keyPair.getCertificate().getPublicKey(), certificates);

    EidasMiddlewareConfig newConfig = config;
    ServiceProviderType newSp = sp;
    try
    {
      if (foundCert.isEmpty())
      {
        String message = "Received TLS certificate does not match requested key";
        log.warn(LOG_MESSAGE_DEFAULT_FORMAT, sp.getName(), message);
        failed.add(sp.getName() + ": " + message);
        return Optional.of(message);
      }
      // save new cert
      newConfig = configurationService.updateKeyPair(keyPairName, foundCert.get());

      newSp = newConfig.getEidConfiguration()
                       .getServiceProvider()
                       .stream()
                       .filter(s -> sp.getName().equals(s.getName()))
                       .findFirst()
                       .orElse(new ServiceProviderType());

      // move pending to current
      if (newSp.getPendingClientKeyPairName() != null)
      {
        newSp.setClientKeyPairName(newSp.getPendingClientKeyPairName());
      }
      succeeded.add(sp.getName());
      return Optional.empty();
    }
    finally
    {
      // delete pending
      newSp.setPendingClientKeyPairName(null);
      configurationService.saveConfiguration(newConfig, false);
    }
  }

  @Override
  void checkCert(ServiceProviderType sp, Date deadline)
  {
    // check current TLS client certificate if it needs to be renewed
    KeyPair kp;
    try
    {
      kp = configurationService.getKeyPair(sp.getClientKeyPairName());
    }
    catch (ConfigurationException e)
    {
      log.info("SP {} has no TLS client certificate, no update performed", sp.getName());
      renewalNotNeeded.add(sp.getName());
      return;
    }

    // check expiration date
    if (kp.getCertificate().getNotAfter().after(deadline))
    {
      log.info("Validity period of TLS client certificate of SP {} still long enough, no update performed",
               sp.getName());
      renewalNotNeeded.add(sp.getName());
      return;
    }

    KeyPair kpToUse;
    // if pending present, use it
    if (sp.getPendingClientKeyPairName() != null)
    {
      try
      {
        kpToUse = configurationService.getKeyPair(sp.getPendingClientKeyPairName());
      }
      catch (ConfigurationException e)
      {
        log.warn("Cannot find pending TLS key pair for SP {} although there seems to be one", sp.getName());
        failed.add(sp.getName() + ": Cannot find pending TLS key pair although there seems to be one");
        return;
      }
    }
    // else current
    else
    {
      kpToUse = kp;
    }

    // if not usable, generate new pending
    if (!canUseKey(kpToUse.getCertificate().getPublicKey()))
    {
      log.info("TLS client key can not be used, generating a new pending key");
      try
      {
        kpToUse = generateAndStoreKeyPair(sp.getName());
      }
      catch (Exception e)
      {
        String message = String.format("Unable to generate new key pair for SP %s", sp.getName());
        log.warn(message, e);
        failed.add(sp.getName() + ": " + message);
        return;
      }
    }

    generateAndSendCsrUnchecked(sp.getName(), kpToUse);
  }

  private Optional<String> generateAndSendCsrUnchecked(String spName, KeyPair kpToUse)
  {
    try
    {
      // generate CSR and put into CMS
      PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(getSubject(spName),
                                                                                                 kpToUse.getCertificate()
                                                                                                        .getPublicKey());
      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(CertificateUtil.getAlgorithm(kpToUse.getKey()));
      CMSProcessableByteArray cms;
      ContentSigner contentSigner = contentSignerBuilder.build(kpToUse.getKey());
      PKCS10CertificationRequest csr = pkcs10Builder.build(contentSigner);
      cms = new CMSProcessableByteArray(new ASN1ObjectIdentifier("1.2.840.113549.1.10"), csr.getEncoded());
      return signAndSend(spName, cms);
    }
    catch (IOException | OperatorCreationException | InvalidCsrException e)
    {
      String message = String.format("Unable to generate CSR for SP %s", spName);
      log.warn(message, e);
      failed.add(spName + ": " + message);
      return Optional.of(message);
    }
  }

  private KeyPair generateAndStoreKeyPair(String spName)
    throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException
  {
    EidasMiddlewareConfig eidasMiddlewareConfig = configurationService.getConfiguration().orElseThrow();
    EidConfiguration eidConfiguration = Optional.ofNullable(eidasMiddlewareConfig.getEidConfiguration()).orElseThrow();
    ServiceProviderType sp = eidConfiguration.getServiceProvider()
                                             .stream()
                                             .filter(s -> spName.equals(s.getName()))
                                             .findFirst()
                                             .orElseThrow();

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    kpg.initialize(384);
    java.security.KeyPair kp = kpg.generateKeyPair();
    Certificate tempCert = CertificateUtil.createSelfSignedCert(kp,
                                                                "CN=DUMMY",
                                                                100,
                                                                SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    String alias = UUID.randomUUID().toString();
    String password = UUID.randomUUID().toString();
    KeyStore keyStore = KeyStoreSupporter.toKeyStore(kp.getPrivate(),
                                                     tempCert,
                                                     alias,
                                                     password,
                                                     KeyStoreSupporter.KeyStoreType.JKS);

    String keyName = Instant.now().toString().concat("-").concat(spName).concat("-TLS Client");
    KeyStoreType keyStoreType;
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
    {
      keyStore.store(bout, password.toCharArray());
      keyStoreType = new KeyStoreType(keyName, bout.toByteArray(), KeyStoreTypeType.JKS, password);
    }
    KeyPairType keyPairType = new KeyPairType(keyName, alias, password, keyName);

    EidasMiddlewareConfig.KeyData keyData = Optional.ofNullable(eidasMiddlewareConfig.getKeyData())
                                                    .orElse(new EidasMiddlewareConfig.KeyData());
    keyData.getKeyStore().add(keyStoreType);
    keyData.getKeyPair().add(keyPairType);
    eidasMiddlewareConfig.setKeyData(keyData);
    sp.setPendingClientKeyPairName(keyName);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    return new KeyPair(keyStore, alias, password);
  }

  @Override
  public Optional<String> generateAndSendCsr(String spName, String keyName)
  {
    synchronized (TlsClientRenewalService.class)
    {
      log.info("Renewing the TLS client certificate with keypair '{}' for service provider: {}", keyName, spName);
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

      ServiceProviderType sp = spOpt.get();
      if (sp.getPendingClientKeyPairName() != null && pendingCsrRepository.existsById(spName))
      {
        String message = "TLS client renewal not possible, there is already a pending key";
        log.warn(message);
        return Optional.of(message);
      }

      try
      {
        KeyPair kp = configurationService.getKeyPair(keyName);
        if (!canUseKey(kp.getCertificate().getPublicKey()))
        {
          String message = "TLS client renewal not possible, key strength not sufficient";
          log.warn(message);
          return Optional.of(message);
        }
        sp.setPendingClientKeyPairName(keyName);
        configurationService.saveConfiguration(config, false);
        return generateAndSendCsrUnchecked(spName, kp);
      }
      catch (Exception e)
      {
        String message = String.format("Unable to send CSR with key %s for SP %s", keyName, spName);
        log.warn(message, e);
        return Optional.of(message);
      }
    }
  }

  @Override
  public Optional<String> generateAndSendCsrWithNewKey(String spName)
  {
    synchronized (TlsClientRenewalService.class)
    {
      log.info("Renewing the TLS client certificate with a newly generated key for service provider: {}", spName);
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

      ServiceProviderType sp = spOpt.get();
      if (sp.getPendingClientKeyPairName() != null && pendingCsrRepository.existsById(spName))
      {
        String message = "TLS client renewal not possible, there is already a pending key";
        log.warn(message);
        return Optional.of(message);
      }

      try
      {
        KeyPair kp = generateAndStoreKeyPair(spName);
        return generateAndSendCsrUnchecked(spName, kp);
      }
      catch (Exception e)
      {
        String message = String.format("Unable to send CSR with new key for SP %s", spName);
        log.warn(message, e);
        return Optional.of(message);
      }
    }
  }

  @Override
  public Optional<Date> currentTlsCertValidUntil(String spName)
  {
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
    if (spOpt.get().getClientKeyPairName() == null)
    {
      return Optional.empty();
    }

    try
    {
      KeyPair kp = configurationService.getKeyPair(spOpt.get().getClientKeyPairName());
      return Optional.of(kp.getCertificate().getNotAfter());
    }
    catch (ConfigurationException e)
    {
      return Optional.empty();
    }
  }
}
