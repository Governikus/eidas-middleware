package de.governikus.eumw.configuration.migration.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.ContactType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.OrganizationType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.configuration.migration.models.eidas.ConfigHolder;
import de.governikus.eumw.configuration.migration.models.poseidas.CoreConfigurationDto;
import de.governikus.eumw.configuration.migration.models.poseidas.PkiConnectorConfigurationDto;
import de.governikus.eumw.configuration.migration.models.poseidas.PoseidasConfigurator;
import de.governikus.eumw.configuration.migration.models.poseidas.ServiceProviderDto;
import de.governikus.eumw.configuration.migration.models.poseidas.SslKeysDto;
import de.governikus.eumw.configuration.migration.utils.PasswordGenerator;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidasstarterkit.EidasContactPerson;
import de.governikus.eumw.eidasstarterkit.EidasMetadataNode;
import de.governikus.eumw.eidasstarterkit.EidasOrganisation;
import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.utils.key.SecurityProvider;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class ConfigurationMigrationService
{

  private static final String BLACK_LIST_TRUST_ANCHOR_NAME = "BlackListTrustAnchor";

  private static final String MASTER_LIST_TRUST_ANCHOR_NAME = "MasterListTrustAnchor";

  private static final String DVCA_CLIENT_KEY_PAIR = "DvcaClientKeyPair";

  private static final String DVCA_KEY_STORE = "DvcaKeyStore";

  private static final String METADATA_SIGNATURE_VERIFICATION_CERTIFICATE = "metadataSignatureVerificationCertificate";

  private final List<DvcaConfigurationType> dvcaConfigurationTypeList = new ArrayList<>();

  private final List<KeyStoreType> keyStoreTypeList = new ArrayList<>();

  private final List<KeyPairType> keyPairTypeList = new ArrayList<>();

  private final List<CertificateType> certificateTypeList = new ArrayList<>();

  private ConfigHolder loadEidasProperties(String pathToConfigFolder) throws IOException
  {
    ConfigHolder configHolder = new ConfigHolder();
    configHolder.loadProperties(pathToConfigFolder);
    return configHolder;
  }

  private CoreConfigurationDto loadPoseidasProperties(String pathToConfigFolder) throws Exception
  {
    PoseidasConfigurator poseidasConfigurator = new PoseidasConfigurator();
    return poseidasConfigurator.loadConfig(pathToConfigFolder);
  }

  public EidasMiddlewareConfig migrateOldConfig(String pathToConfigFolder)
  {

    ConfigHolder configHolder;
    try
    {
      configHolder = loadEidasProperties(pathToConfigFolder);
    }
    catch (IOException e)
    {
      log.error("Can not load eidasmiddleware.properties", e);
      return null;
    }
    CoreConfigurationDto coreConfigurationDto;
    try
    {
      coreConfigurationDto = loadPoseidasProperties(pathToConfigFolder);
    }
    catch (Exception e)
    {
      log.error("Cannot load POSeIDAS.xml", e);
      return null;
    }
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    String serverUrl = configHolder.getServerUrl();
    eidasMiddlewareConfig.setServerUrl(serverUrl);
    log.info("Set server url to {}", serverUrl);

    // TIMER
    log.info("Migrate timer configuration");
    de.governikus.eumw.config.TimerConfigurationType newTimerConfigurationType = migrateTimerConfiguration(coreConfigurationDto.getTimerConfiguration(),
                                                                                                           getHoursRefreshCvcBeforeExpires(coreConfigurationDto));
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    eidConfiguration.setTimerConfiguration(newTimerConfigurationType);
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);


    // Service Providers
    log.info("Migrate service providers");
    Map<String, ServiceProviderDto> oldServiceProviderMap = coreConfigurationDto.getServiceProvider();
    List<ServiceProviderType> newServiceProviderList = oldServiceProviderMap.values()
                                                                            .stream()
                                                                            .map(this::migrateServiceProvider)
                                                                            .collect(Collectors.toList());
    eidasMiddlewareConfig.getEidConfiguration().getServiceProvider().addAll(newServiceProviderList);
    eidasMiddlewareConfig.getEidConfiguration().getDvcaConfiguration().addAll(dvcaConfigurationTypeList);
    eidConfiguration.setAllowedEidMeans(String.join(",", coreConfigurationDto.getAllowedDocumentTypes()));

    // Eidas Properties
    log.info("Migrate eidas properties");
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = migrateEidasProperties(configHolder);
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);

    // Add KeyData
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    eidasMiddlewareConfig.setKeyData(keyData);
    keyData.getCertificate().addAll(certificateTypeList);
    keyData.getKeyStore().addAll(keyStoreTypeList);
    keyData.getKeyPair().addAll(keyPairTypeList);

    return eidasMiddlewareConfig;
  }

  private EidasMiddlewareConfig.EidasConfiguration migrateEidasProperties(ConfigHolder configHolder)
  {
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setPublicServiceProviderName(configHolder.getEntityIDInt());
    eidasConfiguration.setCountryCode(configHolder.getCountryCode());
    eidasConfiguration.setDoSign(configHolder.isDoSignMetadata());
    eidasConfiguration.setMetadataValidity(30);
    EidasContactPerson oldContactPerson = configHolder.getContactPerson();
    eidasConfiguration.setContactPerson(new ContactType(oldContactPerson.getCompany(), oldContactPerson.getGivenName(),
                                                        oldContactPerson.getSurName(), oldContactPerson.getEmail(),
                                                        oldContactPerson.getTel()));
    EidasOrganisation oldOrganization = configHolder.getOrganization();
    eidasConfiguration.setOrganization(new OrganizationType(oldOrganization.getDisplayName(), oldOrganization.getName(),
                                                            oldOrganization.getLangId(), oldOrganization.getUrl()));
    try
    {
      if (configHolder.getAppSignatureKeyPair() != null)
      {
        String signing = createAndGetKeyStoreName(configHolder,
                                                  configHolder.getAppSignatureKeyStoreType(),
                                                  ConfigHolder.KEY_APP_SIGN_ALIAS,
                                                  ConfigHolder.KEY_APP_SIGN_PIN,
                                                  "Signing",
                                                  configHolder.getAppSignatureKeyPair());
        eidasConfiguration.setSignatureKeyPairName(signing);
      }
    }
    catch (Exception e)
    {
      log.error("Cannot migrate eidas middleware signature keystore", e);
    }
    try
    {
      CertificateType metadataSignatureVerifyCertificate = new CertificateType(METADATA_SIGNATURE_VERIFICATION_CERTIFICATE,
                                                                               configHolder.getMetadataSignatureCert()
                                                                                           .getEncoded(),
                                                                               null, null);
      certificateTypeList.add(metadataSignatureVerifyCertificate);
      eidasConfiguration.setMetadataSignatureVerificationCertificateName(METADATA_SIGNATURE_VERIFICATION_CERTIFICATE);
    }
    catch (CertificateException e)
    {
      log.error("Cannot migrate metadata signature verify certificate", e);
    }

    // METADATA
    log.info("Migrate connector metadata");
    List<ConnectorMetadataType> connectorMetadata = migrateConnectorMetadata(configHolder);
    eidasConfiguration.getConnectorMetadata().addAll(connectorMetadata);
    return eidasConfiguration;
  }

  private List<ConnectorMetadataType> migrateConnectorMetadata(ConfigHolder configHolder)
  {
    File providerConfigDir;
    try
    {
      providerConfigDir = configHolder.getProviderConfigDir();
    }
    catch (IOException e)
    {
      log.error("Cannot migrate connector metadata because path is not available", e);
      return new ArrayList<>();
    }

    log.info("Migrate connector metadata from {}", providerConfigDir);
    File[] files = providerConfigDir.listFiles(pathname -> pathname.getAbsolutePath().endsWith(".xml"));

    List<ConnectorMetadataType> metadataList = new ArrayList<>();
    if (ArrayUtils.isEmpty(files))
    {
      log.warn("No connector metadata present");
    }
    else
    {
      for ( File f : files )
      {
        try (FileInputStream is = new FileInputStream(f))
        {
          byte[] metaByte = is.readAllBytes();
          EidasMetadataNode metaNode = EidasSaml.parseMetaDataNode(new ByteArrayInputStream(metaByte),
                                                                   configHolder.getMetadataSignatureCert(),
                                                                   true);
          metadataList.add(new ConnectorMetadataType(metaByte, metaNode.getEntityId()));
        }
        catch (Exception e)
        {
          log.error("Cannot migrate connector metadata from file {}", f.getName(), e);
        }
      }
    }

    return metadataList;
  }

  private String createAndGetKeyStoreName(ConfigHolder configHolder,
                                          String keyStoreType,
                                          String alias,
                                          String password,
                                          String name,
                                          Utils.X509KeyPair oldKeyPair)
    throws IOException, GeneralSecurityException
  {
    KeyStore keyStore;
    if ("JKS".equals(keyStoreType))
    {
      keyStore = KeyStore.getInstance(keyStoreType);
    }
    else
    {
      keyStore = KeyStore.getInstance(keyStoreType, SecurityProvider.BOUNCY_CASTLE_PROVIDER);
    }
    keyStore.load(null, null);
    keyStore.setKeyEntry(configHolder.getProperties().getProperty(alias),
                         oldKeyPair.getKey(),
                         configHolder.getProperties().getProperty(password).toCharArray(),
                         oldKeyPair.getChain());
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
    {
      keyStore.store(bout, configHolder.getProperties().getProperty(password).toCharArray());
      byte[] ksAsByteArray = bout.toByteArray();
      KeyStoreType newKeyStoreType = new KeyStoreType(configHolder.getProperties().getProperty(alias) + name,
                                                      ksAsByteArray, KeyStoreTypeType.fromValue(keyStoreType),
                                                      configHolder.getProperties().getProperty(password));

      KeyPairType keyPairType = new KeyPairType(configHolder.getProperties().getProperty(alias) + name + "KeyPair",
                                                configHolder.getProperties().getProperty(alias),
                                                configHolder.getProperties().getProperty(password),
                                                newKeyStoreType.getName());
      keyStoreTypeList.add(newKeyStoreType);
      keyPairTypeList.add(keyPairType);
      return keyPairType.getName();
    }
  }

  private ServiceProviderType migrateServiceProvider(ServiceProviderDto oldServiceProviderDto)
  {
    ServiceProviderType serviceProviderType = new ServiceProviderType();
    String entityID = oldServiceProviderDto.getEntityID();
    log.info("Migrate service provider {}", entityID);
    serviceProviderType.setName(entityID);
    serviceProviderType.setEnabled(oldServiceProviderDto.isEnabled());
    serviceProviderType.setCVCRefID(oldServiceProviderDto.getEpaConnectorConfiguration().getCVCRefID());
    PkiConnectorConfigurationDto pkiConnectorConfiguration = oldServiceProviderDto.getEpaConnectorConfiguration()
                                                                                  .getPkiConnectorConfiguration();
    Optional<SslKeysDto> oldDvcaKeys = pkiConnectorConfiguration.getSslKeys()
                                                                .values()
                                                                .stream()
                                                                .filter(sslKeysDto -> sslKeysDto.getId()
                                                                                                .equals(pkiConnectorConfiguration.getRestrictedIdService()
                                                                                                                                 .getSslKeysId()))
                                                                .findAny();
    if (oldDvcaKeys.isPresent())
    {
      try
      {
        KeyPairType keyPair = createKeyPair(entityID, oldDvcaKeys.get());
        if (keyPair != null)
        {
          serviceProviderType.setClientKeyPairName(keyPair.getName());
        }
        serviceProviderType.setDvcaConfigurationName(getDvcaName(pkiConnectorConfiguration));
      }
      catch (Exception e)
      {
        log.error("Cannot migrate dvca configuration for service provider {}", entityID, e);
        return serviceProviderType;
      }
    }
    else
    {
      log.warn("No dvca configuration for service provider {} present", entityID);
    }
    return serviceProviderType;
  }

  private KeyPairType createKeyPair(String entityID, SslKeysDto sslKeysDto)
    throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
  {
    Utils.X509KeyPair clientKeyPair = sslKeysDto.getClientKeyPair();
    if (clientKeyPair.getKey() != null && ArrayUtils.isNotEmpty(clientKeyPair.getChain()))
    {
      KeyStore keyStore = KeyStore.getInstance("PKCS12", SecurityProvider.BOUNCY_CASTLE_PROVIDER);
      keyStore.load(null, null);
      char[] password = PasswordGenerator.generateRandomPassword();
      keyStore.setKeyEntry(entityID + DVCA_CLIENT_KEY_PAIR, clientKeyPair.getKey(), password, clientKeyPair.getChain());
      try (ByteArrayOutputStream bout = new ByteArrayOutputStream())
      {
        keyStore.store(bout, password);
        byte[] ksAsByteArray = bout.toByteArray();
        KeyStoreType keyStoreType = new KeyStoreType(entityID + DVCA_KEY_STORE, ksAsByteArray,
                                                     KeyStoreTypeType.fromValue(keyStore.getType()
                                                                                        .toUpperCase(Locale.ROOT)),
                                                     new String(password));
        keyStoreTypeList.add(keyStoreType);
        KeyPairType keyPairType = new KeyPairType(entityID + DVCA_CLIENT_KEY_PAIR, entityID + DVCA_CLIENT_KEY_PAIR,
                                                  new String(password), entityID + DVCA_KEY_STORE);
        keyPairTypeList.add(keyPairType);
        return keyPairType;
      }
    }
    return null;
  }

  private String getDvcaName(PkiConnectorConfigurationDto pkiConnectorConfiguration)
  {
    Optional<DvcaConfigurationType> dvcaConf = dvcaConfigurationTypeList.stream()
                                                                        .filter(dvcaConfigurationType -> isSameDvcaConf(pkiConnectorConfiguration,
                                                                                                                        dvcaConfigurationType))
                                                                        .findFirst();
    if (dvcaConf.isPresent())
    {
      return dvcaConf.get().getName();
    }
    DvcaConfigurationType newDvcaConf = createNewDvcaConf(pkiConnectorConfiguration);
    dvcaConfigurationTypeList.add(newDvcaConf);
    return newDvcaConf.getName();
  }

  private DvcaConfigurationType createNewDvcaConf(PkiConnectorConfigurationDto pkiConf)
  {
    DvcaConfigurationType newDvcaConfiguration = new DvcaConfigurationType();
    UriComponents url = UriComponentsBuilder.fromHttpUrl(pkiConf.getPassiveAuthService().getUrl()).build();
    newDvcaConfiguration.setName(url.getHost());
    newDvcaConfiguration.setPassiveAuthServiceUrl(pkiConf.getPassiveAuthService().getUrl());

    String restrictedIdUrl = pkiConf.getRestrictedIdService().getUrl();
    if (StringUtils.startsWith(restrictedIdUrl, "https://berca-p1.d-trust.net/ps/dvsd_v2"))
    {
      restrictedIdUrl = "https://berca-p1.d-trust.net/ps/dvsd_v2/v1_1";
    }
    newDvcaConfiguration.setRestrictedIdServiceUrl(restrictedIdUrl);

    String terminalAuthenticationUrl = pkiConf.getTerminalAuthService().getUrl();
    if (StringUtils.startsWith(terminalAuthenticationUrl, "https://berca-p1.d-trust.net/ps/dvca-at"))
    {
      terminalAuthenticationUrl = "https://berca-p1.d-trust.net/ps/dvca-at/v1_1";
    }
    newDvcaConfiguration.setTerminalAuthServiceUrl(terminalAuthenticationUrl);

    try
    {
      CertificateType blackListTrustAnchor = new CertificateType();
      blackListTrustAnchor.setName(newDvcaConfiguration.getName() + BLACK_LIST_TRUST_ANCHOR_NAME);
      blackListTrustAnchor.setCertificate(pkiConf.getBlackListTrustAnchor().getEncoded());
      certificateTypeList.add(blackListTrustAnchor);
      newDvcaConfiguration.setBlackListTrustAnchorCertificateName(blackListTrustAnchor.getName());
    }
    catch (CertificateEncodingException | NullPointerException e)
    {
      log.error("Cannot encode blacklist trust anchor certificate", e);
    }
    try
    {
      CertificateType masterListTrustAnchor = new CertificateType();
      masterListTrustAnchor.setName(newDvcaConfiguration.getName() + MASTER_LIST_TRUST_ANCHOR_NAME);
      masterListTrustAnchor.setCertificate(pkiConf.getMasterListTrustAnchor().getEncoded());
      certificateTypeList.add(masterListTrustAnchor);
      newDvcaConfiguration.setMasterListTrustAnchorCertificateName(masterListTrustAnchor.getName());
    }
    catch (CertificateEncodingException | NullPointerException e)
    {
      log.error("Cannot encode masterlist trust anchor certificate", e);
    }
    try
    {
      Optional<SslKeysDto> optionalSslKeysDto = pkiConf.getSslKeys()
                                                       .values()
                                                       .stream()
                                                       .filter(sslKeysDto -> sslKeysDto.getId()
                                                                                       .equals(pkiConf.getPassiveAuthService()
                                                                                                      .getSslKeysId()))
                                                       .findFirst();
      if (optionalSslKeysDto.isPresent())
      {
        CertificateType dvcaSslCertificate = new CertificateType();
        dvcaSslCertificate.setCertificate(optionalSslKeysDto.get().getServerCertificate().getEncoded());
        dvcaSslCertificate.setName(newDvcaConfiguration.getName() + "ServerCertificate");
        newDvcaConfiguration.setServerSSLCertificateName(dvcaSslCertificate.getName());
        certificateTypeList.add(dvcaSslCertificate);
      }
      else
      {
        log.info("No DVCA server certificate in POSeIDAS.xml present");
      }
    }
    catch (CertificateEncodingException | NullPointerException e)
    {
      log.error("Cannot encode DVCA server certificate", e);
    }

    return newDvcaConfiguration;
  }

  private boolean isSameDvcaConf(PkiConnectorConfigurationDto pkiConf, DvcaConfigurationType dvcaConfigurationType)
  {
    return pkiConf.getPassiveAuthService().getUrl().equals(dvcaConfigurationType.getPassiveAuthServiceUrl())
           && pkiConf.getTerminalAuthService().getUrl().equals(dvcaConfigurationType.getTerminalAuthServiceUrl())
           && pkiConf.getRestrictedIdService().getUrl().equals(dvcaConfigurationType.getRestrictedIdServiceUrl());
  }

  private de.governikus.eumw.config.TimerConfigurationType migrateTimerConfiguration(TimerConfigurationType oldTimerConfiguration,
                                                                                     int hoursRefreshCvcBeforeExpires)
  {
    de.governikus.eumw.config.TimerConfigurationType newTimerConfiguration = new de.governikus.eumw.config.TimerConfigurationType();

    // BLackList
    TimerType timerTypeBlackList = mapOldTimerTypeToNewTimerType(oldTimerConfiguration.getBlacklistRenewal());
    newTimerConfiguration.setBlacklistRenewal(timerTypeBlackList);

    // CertRenewal
    TimerType timerTypeCertRenewal = mapOldTimerTypeToNewTimerType(oldTimerConfiguration.getCertRenewal());
    newTimerConfiguration.setCertRenewal(new TimerTypeCertRenewal(timerTypeCertRenewal.getLength(),
                                                                  timerTypeCertRenewal.getUnit(),
                                                                  hoursRefreshCvcBeforeExpires));

    // MasterListRenewal
    TimerType timerTypeMasterListRenewal = mapOldTimerTypeToNewTimerType(oldTimerConfiguration.getMasterAndDefectListRenewal());
    newTimerConfiguration.setMasterAndDefectListRenewal(timerTypeMasterListRenewal);

    // CRLRenewal
    TimerType timerTypeCrlRenewal = mapOldTimerTypeToNewTimerType(oldTimerConfiguration.getCrlRenewal());
    newTimerConfiguration.setCrlRenewal(timerTypeCrlRenewal);

    return newTimerConfiguration;
  }

  private int getHoursRefreshCvcBeforeExpires(CoreConfigurationDto coreConfigurationDto)
  {
    Set<Integer> hoursRefreshCVCBeforeExpiresSet = coreConfigurationDto.getServiceProvider()
                                                                       .values()
                                                                       .parallelStream()
                                                                       .map(sp -> sp.getEpaConnectorConfiguration()
                                                                                    .getHoursRefreshCVCBeforeExpires())
                                                                       .collect(Collectors.toSet());
    return hoursRefreshCVCBeforeExpiresSet.size() == 1 ? hoursRefreshCVCBeforeExpiresSet.iterator().next() : 20;
  }

  private TimerType mapOldTimerTypeToNewTimerType(de.governikus.eumw.poseidas.config.schema.TimerType oldTimerType)
  {
    return new TimerType(oldTimerType.getLength(),
                         oldTimerType.getUnit() == Calendar.MINUTE ? TimerUnit.MINUTES : TimerUnit.HOURS);
  }
}
