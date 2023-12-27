/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.info.BuildProperties;

import de.governikus.eumw.config.ConnectorMetadataType;
import de.governikus.eumw.config.ContactType;
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.OrganizationType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.server.idprovider.config.Configuration;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationRepository;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.poseidas.service.MetadataService;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@ExtendWith(MockitoExtension.class)
class MetadataServiceImplTest
{

  private static final String MIDDLEWARE_SIGN = "middleware-sign";

  private static final String MIDDLEWARE_CRYPT = "middleware-crypt";

  private static final String COMPANY = "company";

  private static final String GIVENNAME = "givenname";

  private static final String SURNAME = "surname";

  private static final String EMAIL = "email";

  private static final String TELEPHONE = "telephone";

  private static final String DISPLAYNAME = "displayname";

  private static final String NAME = "name";

  private static final String LANGUAGE = "language";

  private static final String URL = "url";

  @Mock
  BuildProperties buildProperties;

  @Mock
  HSMServiceHolder hsmServiceHolder;

  @Mock
  ConfigurationRepository configurationRepository;

  private MetadataService metadataService;

  /**
   * In order to run builds on jenkins in parallel, the temp dirs should be unique and random.
   */
  @BeforeEach
  public void setUp() throws Exception
  {
    Configuration configuration = new Configuration();
    configuration.setXmlConfigBlob(createConfiguration());
    Mockito.when(configurationRepository.findById(1L)).thenReturn(java.util.Optional.of(configuration));
    metadataService = new MetadataServiceImpl(buildProperties, hsmServiceHolder,
                                              new ConfigurationService(configurationRepository));
  }



  @Test
  void whenGetMetadataCalledExpectMetadataByteArray()
  {
    Mockito.when(buildProperties.getVersion()).thenReturn("2.0");
    byte[] metadata = metadataService.getMetadata();
    String metadataAsString = new String(metadata);

    Assertions.assertTrue(ArrayUtils.isNotEmpty(metadata));
    Assertions.assertTrue(metadataAsString.contains(COMPANY));
    Assertions.assertTrue(metadataAsString.contains(GIVENNAME));
    Assertions.assertTrue(metadataAsString.contains(SURNAME));
    Assertions.assertTrue(metadataAsString.contains(EMAIL));
    Assertions.assertTrue(metadataAsString.contains(TELEPHONE));
    Assertions.assertTrue(metadataAsString.contains(DISPLAYNAME));
    Assertions.assertTrue(metadataAsString.contains(NAME));
    Assertions.assertTrue(metadataAsString.contains(LANGUAGE));
    Assertions.assertTrue(metadataAsString.contains("http://serverURL" + ContextPaths.EIDAS_CONTEXT_PATH
                                                    + ContextPaths.REQUEST_RECEIVER));
    Assertions.assertTrue(metadataAsString.contains("http://serverURL" + ContextPaths.EIDAS_CONTEXT_PATH
                                                    + ContextPaths.METADATA));
    Assertions.assertTrue(metadataAsString.contains("2.0"));
    // part of sig cert
    Assertions.assertTrue(metadataAsString.contains("MIIEsDCCApigAwIBAgIEZXgnNjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9t"));
    Assertions.assertFalse(metadataAsString.contains("KeyDescriptor use=\"encryption\""));
  }

  private byte[] createConfiguration() throws IOException
  {
    EidasMiddlewareConfig config = new EidasMiddlewareConfig();
    config.setServerUrl("http://serverURL");
    var keyData = new EidasMiddlewareConfig.KeyData();
    config.setKeyData(keyData);
    config.getKeyData()
          .getKeyStore()
          .add(new KeyStoreType(MIDDLEWARE_SIGN,
                                MetadataServiceImplTest.class.getResourceAsStream("/eidasmiddlewareProperties/middleware-sign.p12")
                                                             .readAllBytes(),
                                KeyStoreTypeType.PKCS_12, "123456"));
    config.getKeyData().getKeyPair().add(new KeyPairType(MIDDLEWARE_SIGN, MIDDLEWARE_SIGN, "123456", MIDDLEWARE_SIGN));

    config.getKeyData()
          .getKeyStore()
          .add(new KeyStoreType(MIDDLEWARE_CRYPT,
                                MetadataServiceImplTest.class.getResourceAsStream("/eidasmiddlewareProperties/middleware-crypt.jks")
                                                             .readAllBytes(),
                                KeyStoreTypeType.JKS, "123456"));
    config.getKeyData()
          .getKeyPair()
          .add(new KeyPairType(MIDDLEWARE_CRYPT, MIDDLEWARE_CRYPT, "123456", MIDDLEWARE_CRYPT));

    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.getConnectorMetadata()
                      .add(new ConnectorMetadataType("metadata".getBytes(StandardCharsets.UTF_8), null));
    eidasConfiguration.setDoSign(true);
    eidasConfiguration.setSignatureKeyPairName(MIDDLEWARE_SIGN);
    eidasConfiguration.setDecryptionKeyPairName(MIDDLEWARE_CRYPT);
    eidasConfiguration.setCountryCode("DE");
    eidasConfiguration.setContactPerson(new ContactType(COMPANY, GIVENNAME, SURNAME, EMAIL, TELEPHONE));
    eidasConfiguration.setOrganization(new OrganizationType(DISPLAYNAME, NAME, LANGUAGE, URL));
    config.setEidasConfiguration(eidasConfiguration);
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    DvcaConfigurationType dvcaConfiguration = new DvcaConfigurationType();
    dvcaConfiguration.setName(NAME);
    dvcaConfiguration.setTerminalAuthServiceUrl("taurl");
    dvcaConfiguration.setRestrictedIdServiceUrl("riurl");
    dvcaConfiguration.setPassiveAuthServiceUrl("paurl");
    dvcaConfiguration.setDvcaCertificateDescriptionServiceUrl("cdurl");
    eidConfiguration.getDvcaConfiguration().add(dvcaConfiguration);
    TimerConfigurationType timerConfigurationType = new TimerConfigurationType();
    timerConfigurationType.setCertRenewal(new TimerTypeCertRenewal(1, TimerUnit.MINUTES, 1));
    timerConfigurationType.setBlacklistRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setMasterAndDefectListRenewal(new TimerType(1, TimerUnit.MINUTES));
    timerConfigurationType.setCrlRenewal(new TimerType(1, TimerUnit.MINUTES));
    eidConfiguration.setTimerConfiguration(timerConfigurationType);
    config.setEidConfiguration(eidConfiguration);

    return XmlHelper.marshalObject(config).getBytes(StandardCharsets.UTF_8);
  }

}
