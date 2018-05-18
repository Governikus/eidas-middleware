/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model.poseidasxml;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Optional;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.web.handler.HandlerHolder;
import de.governikus.eumw.configuration.wizard.web.model.AbstractConfigurationLoader;
import de.governikus.eumw.configuration.wizard.web.model.KeystoreForm;
import de.governikus.eumw.poseidas.config.schema.EPAConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiServiceType;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.poseidas.config.schema.TimerType;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.exceptions.KeyGenerationException;
import de.governikus.eumw.utils.key.exceptions.KeyStoreCreationFailedException;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 08:46 <br>
 * <br>
 * this class will represent the form for the view that is used to fill the poseidas core configuration
 */
@Slf4j
@Data
public class PoseidasCoreConfigForm extends AbstractConfigurationLoader
{

  /**
   * POSeIDAS config timer unit
   */
  public static final int UNIT = 11;

  /**
   * POSeIDAS config timer value
   */
  public static final int LENGTH = 2;

  /**
   * max pending requests
   */
  public static final int SESSION_MAX_PENDING_REQUESTS = 500;

  /**
   * certificate warning margin
   */
  public static final int CERTIFICATE_WARNING_MARGIN = 200;

  /**
   * hours to refresh cvc before it expires
   */
  public static final int HOURS_REFRESH_BEFORE_EXPIRE = 48;

  /**
   * this file represents an uploaded preconfigured file that the user might have uploaded or loaded with the
   * system-start
   */
  private MultipartFile poseidasConfigXmlFile;

  /**
   * this service provider will represent the service provider that is currently edited in the html view
   */
  private ServiceProviderForm serviceProvider = new ServiceProviderForm();

  /**
   * this will hold all values for the Poseidas core cofiguration
   */
  private PoseidasCoreConfiguration coreConfig;

  /**
   * constructor to initialize this instance properly
   */
  public PoseidasCoreConfigForm()
  {
    this.coreConfig = new PoseidasCoreConfiguration();

    TimerConfigurationType timerConfiguration = new TimerConfigurationType();
    this.coreConfig.setTimerConfiguration(timerConfiguration);

    // setting default values for renewals. These can be configured later in the view in advanced settings
    TimerType certRenewal = new TimerType();
    certRenewal.setLength(LENGTH);
    certRenewal.setUnit(UNIT);
    timerConfiguration.setCertRenewal(certRenewal);

    TimerType blacklistRenewal = new TimerType();
    blacklistRenewal.setLength(LENGTH);
    blacklistRenewal.setUnit(UNIT);
    timerConfiguration.setBlacklistRenewal(blacklistRenewal);

    TimerType masterAndDefectListRenewal = new TimerType();
    masterAndDefectListRenewal.setLength(LENGTH);
    masterAndDefectListRenewal.setUnit(UNIT);
    timerConfiguration.setMasterAndDefectListRenewal(masterAndDefectListRenewal);
  }

  /**
   * loads the configuration from a file
   *
   * @param poseidasXml the configuration file that should hold the configuration
   */
  public boolean loadConfiguration(final File poseidasXml)
  {
    if (!poseidasXml.exists())
    {
      log.debug("no poseidas xml file found at '{}'", poseidasXml);
      return false;
    }
    log.trace("loading configuration from poseidas xml file: {}", poseidasXml);
    setCoreConfig(XmlHelper.unmarshal(poseidasXml, PoseidasCoreConfiguration.class));
    getServiceProviderType().ifPresent(this::setServiceProviderFormValues);
    return true;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean loadConfiguration(MultipartFile configurationFile)
  {
    log.trace("loading configuration from poseidas xml input-stream");
    try
    {
      setCoreConfig(XmlHelper.unmarshal(IOUtils.toString(configurationFile.getBytes(),
                                                         StandardCharsets.UTF_8.name()),
                                        PoseidasCoreConfiguration.class));
    }
    catch (IOException e)
    {
      log.error("could not read poseidas xml input stream", e);
      return false;
    }
    getServiceProviderType().ifPresent(this::setServiceProviderFormValues);
    return true;
  }

  /**
   * will set the values of the configuration into the field {@link #serviceProvider}
   *
   * @param serviceProviderType the service provider from the read configuration file
   */
  private void setServiceProviderFormValues(ServiceProviderType serviceProviderType)
  {
    this.serviceProvider.setServiceProvider(serviceProviderType);
    this.serviceProvider.setEntityID(serviceProviderType.getEntityID());
    PkiConnectorConfigurationType pkiConnectorConfigurationType = serviceProviderType.getEPAConnectorConfiguration()
                                                                                     .getPkiConnectorConfiguration();
    // @formatter:off
    getCertificate("blacklist-trust-anchor",
                   pkiConnectorConfigurationType.getBlackListTrustAnchor()).ifPresent(this.serviceProvider::setBlackListTrustAnchor);
    getCertificate("defectlist-trust-anchor",
                   pkiConnectorConfigurationType.getDefectListTrustAnchor()).ifPresent(this.serviceProvider::setDefectListTrustAnchor);
    getCertificate("masterlist-trust-anchor",
                   pkiConnectorConfigurationType.getMasterListTrustAnchor()).ifPresent(this.serviceProvider::setMasterListTrustAnchor);
    // @formatter:on

    String policyImplementationId = serviceProviderType.getEPAConnectorConfiguration()
                                                       .getPkiConnectorConfiguration()
                                                       .getPolicyImplementationId();
    try
    {
      this.serviceProvider.setPolicyID(getPolicyImplementationId(serviceProviderType));
    }
    catch (IllegalArgumentException ex)
    {
      log.warn("could not parse policy implementation id '{}': {}", policyImplementationId, ex.getMessage());
    }
    getSslKeysForm(serviceProviderType).ifPresent(this.serviceProvider::setSslKeysForm);
  }

  /**
   * tries to read the ssl key configuration from the given service provider
   *
   * @param serviceProviderType the service provider configuration from the read poseidas.xml
   * @return an empty if not present or not readable, the {@link SslKeysForm} otherwise
   */
  private Optional<SslKeysForm> getSslKeysForm(ServiceProviderType serviceProviderType)
  {
    return getPkiConnectorConfig(serviceProviderType).flatMap(pkiConfig -> getSslKeysForm(pkiConfig.getSslKeys()));
  }

  /**
   * tries to create a {@link SslKeysForm} from the given list. We expect the list to hold exactly a single
   * entry not more. If more entries are found the first entry will be used and the rest will be ignored
   *
   * @param sslKeysTypeList a list of all ssl key configurations
   * @return an empty if no ssl key configurations are present or if the keys could not be read, the first
   *         entry of the ssl keys configuration else
   */
  private Optional<SslKeysForm> getSslKeysForm(List<SslKeysType> sslKeysTypeList)
  {
    if (sslKeysTypeList == null || sslKeysTypeList.isEmpty())
    {
      return Optional.empty();
    }
    SslKeysType sslKeysType = sslKeysTypeList.get(0);
    SslKeysForm.SslKeysFormBuilder builder = SslKeysForm.builder().sslKeysType(sslKeysType);
    getCertificate("dvca-ssl-server-certificate",
                   sslKeysType.getServerCertificate()).ifPresent(builder::serverCertificate);
    getKeystore(sslKeysType).ifPresent(builder::clientKeyForm);
    return Optional.of(builder.build());
  }

  /**
   * tries to read the ssl keys configuration if present from the given configuration
   *
   * @param sslKeysType the ssl keys-type configuration
   * @return an empty if the keys could not be read or are not present, the keystore else
   */
  private Optional<KeystoreForm> getKeystore(SslKeysType sslKeysType)
  {
    if (sslKeysType.getClientCertificate() == null || sslKeysType.getClientCertificate().isEmpty())
    {
      return Optional.empty();
    }
    if (sslKeysType.getClientKey() == null || sslKeysType.getClientKey().length == 0)
    {
      log.warn("private key of SSL keys seems to be empty");
      return Optional.empty();
    }

    final String pseudoPin = "123456";
    final String pseudoAlias = "client";
    byte[] certificate = sslKeysType.getClientCertificate().get(0);
    KeyStore keyStore;
    try
    {
      keyStore = KeyStoreSupporter.toKeyStore(sslKeysType.getClientKey(),
                                              certificate,
                                              pseudoAlias,
                                              pseudoPin,
                                              KeyStoreSupporter.KeyStoreType.JKS);
    }
    catch (KeyGenerationException | KeyStoreCreationFailedException ex)
    {
      log.error("could not create keystore...", ex);
      return Optional.empty();
    }
    KeystoreForm keystoreForm = KeystoreForm.builder()
                                            .keystoreName("dvca-ssl-client-keystore")
                                            .keystore(keyStore)
                                            .alias(pseudoAlias)
                                            .keystorePassword(pseudoPin)
                                            .privateKeyPassword(pseudoPin)
                                            .build();
    HandlerHolder.getKeystoreHandler().add(keystoreForm);
    return Optional.of(keystoreForm);
  }

  /**
   * tries to access the PKI connector configuration of the service provider
   *
   * @param serviceProviderType the service provider configuration that was read
   * @return en empty if the pki connector configuration is not present, the pki connector config else
   */
  private Optional<PkiConnectorConfigurationType> getPkiConnectorConfig(ServiceProviderType serviceProviderType)
  {
    EPAConnectorConfigurationType epaConnectorConfigurationType = serviceProviderType.getEPAConnectorConfiguration();
    if (epaConnectorConfigurationType == null)
    {
      return Optional.empty();
    }
    return Optional.ofNullable(epaConnectorConfigurationType.getPkiConnectorConfiguration());
  }

  /**
   * tries to extract the policy implementation id from the configuration
   *
   * @param serviceProviderType the service provider configuration
   * @return the matching policy implementation id or {@link PolicyImplementationId#GOV_DVCA} if the value
   *         could not be resolved
   */
  private PolicyImplementationId getPolicyImplementationId(ServiceProviderType serviceProviderType)
  {
    return getPkiConnectorConfig(serviceProviderType).map(pkiConfig -> {
      String policyImplementationId = pkiConfig.getPolicyImplementationId();
      if (StringUtils.isBlank(policyImplementationId))
      {
        return PolicyImplementationId.GOV_DVCA;
      }
      return PolicyImplementationId.fromValue(policyImplementationId).orElse(PolicyImplementationId.GOV_DVCA);
    }).orElse(PolicyImplementationId.GOV_DVCA);
  }

  /**
   * tries to get the service provider configuration from the poseidas.xml
   *
   * @return the service provider configuration of the first entry found within the list
   */
  private Optional<ServiceProviderType> getServiceProviderType()
  {
    if (coreConfig == null)
    {
      return Optional.empty();
    }
    if (coreConfig.getServiceProvider() == null || coreConfig.getServiceProvider().isEmpty())
    {
      return Optional.empty();
    }
    return Optional.of(coreConfig.getServiceProvider().get(0));
  }

  /**
   * saves the application properties form into directory/application.properties file
   *
   * @param directory file path
   * @throws XmlException
   * @throws CertificateEncodingException
   */
  public void save(String directory) throws CertificateEncodingException
  {
    fillCoreConfigWithValues();
    XmlHelper.marshalObjectToFile(coreConfig, directory + "/" + FileNames.POSEIDAS_XML.getFileName());
  }

  /**
   * fill the core config with the values entered into the service provider form
   *
   * @throws CertificateEncodingException
   */
  private void fillCoreConfigWithValues() throws CertificateEncodingException
  {
    coreConfig.setSessionManagerUsesDatabase(true);
    coreConfig.setSessionMaxPendingRequests(SESSION_MAX_PENDING_REQUESTS);
    coreConfig.setCertificateWarningMargin(CERTIFICATE_WARNING_MARGIN);
    // only add path if it is not already there
    if (coreConfig.getServerUrl() != null && !coreConfig.getServerUrl().trim().endsWith("/eidas-middleware"))
    {
      coreConfig.setServerUrl(coreConfig.getServerUrl() + "/eidas-middleware");
    }

    ServiceProviderType newServiceProvider = new ServiceProviderType();
    newServiceProvider.setEntityID(serviceProvider.getEntityID());
    newServiceProvider.setEnabled(true);

    EPAConnectorConfigurationType epa = new EPAConnectorConfigurationType();
    epa.setCVCRefID(serviceProvider.getEntityID());
    epa.setHoursRefreshCVCBeforeExpires(HOURS_REFRESH_BEFORE_EXPIRE);
    epa.setPaosReceiverURL(coreConfig.getServerUrl() + "/paosreceiver");
    epa.setUpdateCVC(true);

    PkiConnectorConfigurationType pki = new PkiConnectorConfigurationType();
    pki.setBlackListTrustAnchor(serviceProvider.getBlackListTrustAnchor().getCertificate().getEncoded());
    pki.setDefectListTrustAnchor(serviceProvider.getDefectListTrustAnchor().getCertificate().getEncoded());
    pki.setMasterListTrustAnchor(serviceProvider.getMasterListTrustAnchor().getCertificate().getEncoded());
    pki.setPolicyImplementationId(serviceProvider.getPolicyID().getValue());

    pki.getSslKeys().add(createSslKeys());

    addDvcaServices(pki);

    epa.setPkiConnectorConfiguration(pki);

    newServiceProvider.setEPAConnectorConfiguration(epa);

    coreConfig.getServiceProvider().clear();
    coreConfig.getServiceProvider().add(newServiceProvider);
  }

  /**
   * @param pki PkiConnectorConfigurationType
   */
  private void addDvcaServices(PkiConnectorConfigurationType pki)
  {
    String sslKeysId = pki.getSslKeys().get(0).getId();
    String terminal;
    String restricted;
    String passive;
    String dvca;

    if (PolicyImplementationId.BUDRU.getValue().equals(pki.getPolicyImplementationId()))
    {
      terminal = "https://berca-ps.d-trust.net/ps/dvca-at";
      restricted = "https://berca-ps.d-trust.net/ps/dvsd_v2";
      passive = "https://berca-ps.d-trust.net/ps/scs";
      dvca = "https://berca-ps.d-trust.net/ps/dvca-at-cert-desc";
    }
    else
    {
      // Governikus dvca
      terminal = "https://dev.governikus-eid.de:9444/gov_dvca/ta-service";
      restricted = "https://dev.governikus-eid.de:9444/gov_dvca/ri-service";
      passive = "https://dev.governikus-eid.de:9444/gov_dvca/pa-service";
      dvca = "https://dev.governikus-eid.de:9444/gov_dvca/certDesc-service";
    }

    PkiServiceType terminalAuthService = new PkiServiceType();
    terminalAuthService.setSslKeysId(sslKeysId);
    terminalAuthService.setUrl(terminal);
    pki.setTerminalAuthService(terminalAuthService);

    PkiServiceType restrictedIdService = new PkiServiceType();
    restrictedIdService.setSslKeysId(sslKeysId);
    restrictedIdService.setUrl(restricted);
    pki.setRestrictedIdService(restrictedIdService);

    PkiServiceType passiveAuthService = new PkiServiceType();
    passiveAuthService.setSslKeysId(sslKeysId);
    passiveAuthService.setUrl(passive);
    pki.setPassiveAuthService(passiveAuthService);

    PkiServiceType dvcaCertDescriptionService = new PkiServiceType();
    dvcaCertDescriptionService.setSslKeysId(sslKeysId);
    dvcaCertDescriptionService.setUrl(dvca);
    pki.setDvcaCertDescriptionService(dvcaCertDescriptionService);
  }

  /**
   * create the ssl keys section for the {@link PkiServiceType} from the {@link PoseidasCoreConfigForm}
   */
  private SslKeysType createSslKeys() throws CertificateEncodingException
  {
    SslKeysType sslKeys = new SslKeysType();
    sslKeys.setId("default");
    sslKeys.getClientCertificate()
           .add(serviceProvider.getSslKeysForm()
                               .getClientKeyForm()
                               .asCertificate()
                               .getCertificate()
                               .getEncoded());
    sslKeys.setClientKey(serviceProvider.getSslKeysForm().getClientKeyForm().getPrivateKey().getEncoded());
    sslKeys.setServerCertificate(serviceProvider.getSslKeysForm()
                                                .getServerCertificate()
                                                .getCertificate()
                                                .getEncoded());
    return sslKeys;
  }

  /**
   * @see #poseidasConfigXmlFile
   */
  public void setPoseidasConfigXmlFile(MultipartFile poseidasConfigXmlFile)
  {
    this.poseidasConfigXmlFile = poseidasConfigXmlFile;
    if (poseidasConfigXmlFile != null && !poseidasConfigXmlFile.isEmpty())
    {
      loadConfiguration(poseidasConfigXmlFile);
    }
  }
}
