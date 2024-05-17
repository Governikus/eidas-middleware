/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.springframework.boot.test.mock.mockito.MockBean;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.config.model.ServiceProviderStatus;
import de.governikus.eumw.poseidas.gov2server.constants.admin.AdminPoseidasConstants;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;
import lombok.SneakyThrows;


/**
 * Add some mock data necessary for service provider tests
 */
class ServiceProviderTestBase extends WebAdminTestBase
{

  static final String SERVICE_PROVIDER = "serviceProvider";

  static final String CVC_REF_ID = "CVCRefID:";

  static final String CHR = "CHR:";

  static final String CAR = "CAR:";

  static final String VALID_FROM = "Valid from:";

  static final String VALID_UNTIL = "Valid until:";

  static final String SUBJECT = "Subject:";

  static final String SUBJECT_URL = "Subject URL:";

  static final String TERMS_OF_USAGE = "Terms of usage:";

  static final String REDIRECT_URL = "Redirect URL:";

  static final String ISSUER = "Issuer:";

  static final String MATCH_URL = "Matches URL:";

  static final String MATCH_LINK = "Matches TLS:";


  static final String ISSUER_URL = "Issuer URL:";

  static final Map<String, String> INFO_MAP;

  static
  {
    INFO_MAP = new HashMap<>();
    INFO_MAP.put(CVC_REF_ID, "cvcRefId");
    INFO_MAP.put(CHR, "Holder");
    INFO_MAP.put(CAR, "Authority");
    INFO_MAP.put(VALID_FROM, "2022-02-22");
    INFO_MAP.put(VALID_UNTIL, "2022-03-22");
    INFO_MAP.put(SUBJECT, "Subject");
    INFO_MAP.put(SUBJECT_URL, "SubjectURL");
    INFO_MAP.put(TERMS_OF_USAGE, "Terms");
    INFO_MAP.put(REDIRECT_URL, "RedirectURL");
    INFO_MAP.put(ISSUER, "Issuer");
    INFO_MAP.put(ISSUER_URL, "IssuerURL");
    INFO_MAP.put(MATCH_URL, "✔");
    INFO_MAP.put(MATCH_LINK, "✔");

  }

  @MockBean
  PermissionDataHandling data;

  @MockBean
  ConfigurationService configurationService;

  Map<String, Object> createPermissionDataInfo() throws ParseException
  {
    HashMap<String, Object> info = new HashMap<>();
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_HOLDERREFERENCE, INFO_MAP.get(CHR));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_CA_REFERENCE, INFO_MAP.get(CAR));
    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH);
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EFFECTIVE_DATE, formatter.parse(INFO_MAP.get(VALID_FROM)));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_EXPIRATION_DATE, getValidUntil(formatter));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_NAME, INFO_MAP.get(SUBJECT));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_SUBJECT_URL, INFO_MAP.get(SUBJECT_URL));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_NAME, INFO_MAP.get(ISSUER));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_ISSUER_URL, INFO_MAP.get(ISSUER_URL));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_TERMS_OF_USAGE_PLAIN_TEXT, INFO_MAP.get(TERMS_OF_USAGE));
    info.put(AdminPoseidasConstants.VALUE_PERMISSION_DATA_REDIRECT_URL, INFO_MAP.get(REDIRECT_URL));
    info.put(AdminPoseidasConstants.VALUE_IS_PUBLIC_CLIENT, true);
    return info;
  }

  private Date getValidUntil(SimpleDateFormat formatter) throws ParseException
  {
    Date rawDate = formatter.parse(INFO_MAP.get(VALID_UNTIL));
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(rawDate);
    calendar.add(Calendar.HOUR, 24);
    return calendar.getTime();
  }

  @SneakyThrows
  protected Optional<EidasMiddlewareConfig> createConfiguration()
  {
    // Create Service Provider
    ServiceProviderType serviceProviderType = new ServiceProviderType(SERVICE_PROVIDER, true, INFO_MAP.get(CVC_REF_ID),
                                                                      "dvca", "client", null);
    ServiceProviderType inactiveProvider = new ServiceProviderType("disabledProvider", false, "otherId", "otherDVCA",
                                                                   "otherClient", null);
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    eidConfiguration.getServiceProvider().add(serviceProviderType);
    eidConfiguration.getServiceProvider().add(inactiveProvider);
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);

    // Create a Key Store
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("keyStore", "keyStore".getBytes(StandardCharsets.UTF_8), KeyStoreTypeType.JKS,
                                 "keyStorePassword"));
    eidasMiddlewareConfig.setKeyData(keyData);

    // Add connector metadata and a validation certificate
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    ConnectorMetadataType validMetadata = new ConnectorMetadataType();
    validMetadata.setValue(ServiceProviderTestBase.class.getResourceAsStream("/configuration/metadata-9443.xml")
                                                        .readAllBytes());
    validMetadata.setEntityID("https://localhost:9443/eIDASDemoApplication/Metadata");
    eidasConfiguration.getConnectorMetadata().add(validMetadata);
    ConnectorMetadataType invalidMetadata = new ConnectorMetadataType();
    invalidMetadata.setValue(ServiceProviderTestBase.class.getResourceAsStream("/configuration/metadata-9445-invalid.xml")
                                                          .readAllBytes());
    invalidMetadata.setEntityID("https://localhost:9445/eIDASDemoApplication/Metadata");
    eidasConfiguration.getConnectorMetadata().add(invalidMetadata);
    eidasConfiguration.setMetadataSignatureVerificationCertificateName("sigCert");
    keyData.getCertificate()
           .add(new CertificateType("sigCert",
                                    ServiceProviderTestBase.class.getResourceAsStream("/configuration/metadata-signer.cer")
                                                                 .readAllBytes(),
                                    null, null));
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);
    return Optional.of(eidasMiddlewareConfig);
  }

  protected ServiceProviderStatus createServiceProviderStatus()
  {
    LocalDateTime now = LocalDateTime.now();
    return ServiceProviderStatus.builder()
                                .cvcPresent(true)
                                .cvcValidUntil(LocalDate.of(2022, 3, 23))
                                .cvcSubjectUrl("SubjectURL")
                                .cvcValidity(true)
                                .cvcTLSLinkStatus(true)
                                .cvcUrlMatch(true)
                                .blackListDVCAAvailability(true)
                                .blackListPresent(true)
                                .blackListLastRetrieval(now)
                                .masterListDVCAAvailability(true)
                                .masterListPresent(true)
                                .masterListLastRetrieval(now)
                                .defectListDVCAAvailability(true)
                                .defectListPresent(true)
                                .defectListLastRetrieval(now)
                                .serviceProviderName(SERVICE_PROVIDER)
                                .enabled(true)
                                .build();
  }
}
