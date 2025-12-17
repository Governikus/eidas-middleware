/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.UnexpectedPage;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationRepository;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test configuration import/export page")
class ImportExportConfigurationControllerTest extends WebAdminTestBase
{

  private final ConfigurationService configurationService;

  private final ConfigurationRepository configurationRepository;

  @Autowired
  public ImportExportConfigurationControllerTest(ConfigurationService configurationService,
                                                 ConfigurationRepository configurationRepository)
  {
    this.configurationService = configurationService;
    this.configurationRepository = configurationRepository;
  }

  @BeforeEach
  void setUp()
  {
    configurationRepository.deleteAll();
  }

  @Test
  void testUploadConfiguration() throws Exception
  {
    assertTrue(configurationService.getConfiguration().isEmpty());
    HtmlPage configurationPage = getConfigurationPage();
    HtmlForm uploadForm = configurationPage.getForms().get(0);
    HtmlFileInput inputField = uploadForm.getInputByName("configurationFile");
    String pathToConfigFile = Objects.requireNonNull(ImportExportConfigurationControllerTest.class.getResource("/configuration/Configuration.xml"))
                                     .toExternalForm();
    inputField.setValueAttribute(pathToConfigFile);
    HtmlPage savedConfig = configurationPage.getHtmlElementById("save").click();
    assertTrue(savedConfig.asNormalizedText().contains("Configuration successfully imported!"));
    assertTrue(configurationService.getConfiguration().isPresent());
  }

  @Test
  void testWhenEmptyInputFiledThenReturnErrorMessage() throws Exception
  {
    HtmlPage pageWithErrorMessage = getConfigurationPage().getHtmlElementById("save").click();
    assertNotNull(pageWithErrorMessage.getHtmlElementById("alertERROR"));
    assertTrue(pageWithErrorMessage.asNormalizedText().contains("Please provide a file in the upload field"));
    assertTrue(configurationService.getConfiguration().isEmpty());
  }

  @Test
  void testWhenWrongFileForInputThenReturnErrorMessage() throws Exception
  {
    HtmlPage configurationPage = getConfigurationPage();
    HtmlForm uploadForm = configurationPage.getForms().get(0);
    HtmlFileInput inputField = uploadForm.getInputByName("configurationFile");
    String pathToConfigFile = Objects.requireNonNull(ImportExportConfigurationControllerTest.class.getResource("/configuration/metadata-9443.xml"))
                                     .toExternalForm();
    inputField.setValueAttribute(pathToConfigFile);
    HtmlPage savedConfig = configurationPage.getHtmlElementById("save").click();
    assertNotNull(savedConfig.getHtmlElementById("alertERROR"));
    assertTrue(savedConfig.asNormalizedText()
                          .contains("Could not upload configuration! See logs for more information"));
    assertTrue(configurationService.getConfiguration().isEmpty());
  }

  @Test
  void testMissingKeysThenReturnErrorMessage() throws Exception
  {
    HtmlPage configurationPage = getConfigurationPage();
    HtmlForm uploadForm = configurationPage.getForms().get(0);
    HtmlFileInput inputField = uploadForm.getInputByName("configurationFile");
    String pathToConfigFile = Objects.requireNonNull(ImportExportConfigurationControllerTest.class.getResource("/configuration/eIDAS_Middleware_configuration_noKeys.xml"))
                                     .toExternalForm();
    inputField.setValueAttribute(pathToConfigFile);
    HtmlPage savedConfig = configurationPage.getHtmlElementById("save").click();
    assertErrorAlert(savedConfig,
                     "Key store SamlKeystore has missing data. (Name/Type/Bytes)",
                     "Key store providerA has missing data. (Name/Type/Bytes)",
                     "Key store test has missing data. (Name/Type/Bytes)",
                     "Certificate asdasdasd has no data.",
                     "Certificate DvcaServerSSL has no data.");
    Optional<EidasMiddlewareConfig> configurationOptional = configurationService.getConfiguration();
    assertFalse(configurationOptional.isEmpty());
    EidasMiddlewareConfig eidasMiddlewareConfig = configurationOptional.get();
    assertEquals(7, eidasMiddlewareConfig.getKeyData().getCertificate().size());
    assertEquals("",
                 eidasMiddlewareConfig.getEidConfiguration()
                                      .getDvcaConfiguration()
                                      .get(0)
                                      .getServerSSLCertificateName());
    assertTrue(eidasMiddlewareConfig.getKeyData().getKeyPair().isEmpty());
    assertNull(eidasMiddlewareConfig.getEidasConfiguration().getDecryptionKeyPairName());
  }

  @Test
  void testUploadWithSupportData() throws Exception
  {
    assertTrue(configurationService.getConfiguration().isEmpty());
    HtmlPage configurationPage = getConfigurationPage();
    HtmlForm uploadForm = configurationPage.getForms().get(0);
    HtmlFileInput inputField = uploadForm.getInputByName("configurationFile");
    String pathToConfigFile = Objects.requireNonNull(ImportExportConfigurationControllerTest.class.getResource("/configuration/Configuration_with_supportdata.xml"))
                                     .toExternalForm();
    inputField.setValueAttribute(pathToConfigFile);
    HtmlPage savedConfig = configurationPage.getHtmlElementById("save").click();
    assertTrue(savedConfig.asNormalizedText().contains("Configuration successfully imported!"));
    assertTrue(configurationService.getConfiguration().isPresent());

    Optional<EidasMiddlewareConfig> configurationOptional = configurationService.getConfiguration();
    assertFalse(configurationOptional.isEmpty());
    EidasMiddlewareConfig eidasMiddlewareConfig = configurationOptional.get();
    assertNull(eidasMiddlewareConfig.getSupportData());
    assertEquals(4, eidasMiddlewareConfig.getKeyData().getCertificate().size());
    assertEquals("serverCertificate",
                 eidasMiddlewareConfig.getEidConfiguration()
                                      .getDvcaConfiguration()
                                      .get(0)
                                      .getServerSSLCertificateName());
  }

  @Test
  void testDownloadWithPrivateKeys() throws Exception
  {
    assertTrue(configurationService.getConfiguration().isEmpty());
    HtmlPage configurationPage = getConfigurationPage();
    HtmlForm uploadForm = configurationPage.getForms().get(0);
    HtmlFileInput inputField = uploadForm.getInputByName("configurationFile");
    String pathToConfigFile = Objects.requireNonNull(ImportExportConfigurationControllerTest.class.getResource("/configuration/Configuration.xml"))
                                     .toExternalForm();
    inputField.setValueAttribute(pathToConfigFile);
    HtmlPage savedConfig = configurationPage.getHtmlElementById("save").click();
    assertTrue(savedConfig.asNormalizedText().contains("Configuration successfully imported!"));
    assertTrue(configurationService.getConfiguration().isPresent());

    UnexpectedPage downloadedConfigObj = configurationPage.getAnchorByHref(ContextPaths.ADMIN_CONTEXT_PATH
                                                                           + ContextPaths.IMPORT_EXPORT_CONFIGURATION
                                                                           + "/downloadWithPrivateKeys")
                                                          .click();
    String downloadedConfigAsString = new String(downloadedConfigObj.getInputStream().readAllBytes(),
                                                 StandardCharsets.UTF_8);
    EidasMiddlewareConfig downloadedMwConfig = XmlHelper.unmarshal(downloadedConfigAsString,
                                                                   EidasMiddlewareConfig.class);

    assertNotNull(downloadedMwConfig.getEidasConfiguration().getContactPerson());
    assertNotNull(downloadedMwConfig.getEidasConfiguration().getOrganization());

    assertFalse(downloadedMwConfig.getEidConfiguration().getDvcaConfiguration().isEmpty());
    assertEquals(1, downloadedMwConfig.getEidConfiguration().getDvcaConfiguration().size());
    assertNotNull(downloadedMwConfig.getEidConfiguration().getTimerConfiguration());
    assertFalse(downloadedMwConfig.getEidConfiguration().getServiceProvider().isEmpty());
    assertEquals(1, downloadedMwConfig.getEidConfiguration().getServiceProvider().size());

    assertFalse(downloadedMwConfig.getKeyData().getCertificate().isEmpty());
    assertEquals(4, downloadedMwConfig.getKeyData().getCertificate().size());
    List<KeyStoreType> keyStores = downloadedMwConfig.getKeyData().getKeyStore();
    assertFalse(keyStores.isEmpty());
    assertEquals(3, keyStores.size());
    for ( KeyStoreType keyStore : keyStores )
    {
      assertNotNull(keyStore.getKeyStore());
    }

    List<KeyPairType> keyPairs = downloadedMwConfig.getKeyData().getKeyPair();
    assertFalse(keyPairs.isEmpty());
    assertEquals(3, keyPairs.size());
    for ( KeyPairType keyPair : keyPairs )
    {
      assertNotNull(keyPair.getPassword());
    }

    assertNull(downloadedMwConfig.getSupportData());
  }

  @Test
  void testDownloadWithoutPrivateKeys() throws Exception
  {
    assertTrue(configurationService.getConfiguration().isEmpty());
    HtmlPage configurationPage = getConfigurationPage();
    HtmlForm uploadForm = configurationPage.getForms().get(0);
    HtmlFileInput inputField = uploadForm.getInputByName("configurationFile");
    String pathToConfigFile = Objects.requireNonNull(ImportExportConfigurationControllerTest.class.getResource("/configuration/Configuration.xml"))
                                     .toExternalForm();
    inputField.setValueAttribute(pathToConfigFile);
    HtmlPage savedConfig = configurationPage.getHtmlElementById("save").click();
    assertTrue(savedConfig.asNormalizedText().contains("Configuration successfully imported!"));
    assertTrue(configurationService.getConfiguration().isPresent());

    UnexpectedPage downloadedConfigObj = configurationPage.getAnchorByHref(ContextPaths.ADMIN_CONTEXT_PATH
                                                                           + ContextPaths.IMPORT_EXPORT_CONFIGURATION
                                                                           + "/downloadWithoutPrivateKeys")
                                                          .click();
    String downloadedConfigAsString = new String(downloadedConfigObj.getInputStream().readAllBytes(),
                                                 StandardCharsets.UTF_8);
    EidasMiddlewareConfig downloadedMwConfig = XmlHelper.unmarshal(downloadedConfigAsString,
                                                                   EidasMiddlewareConfig.class);

    assertNotNull(downloadedMwConfig.getEidasConfiguration().getContactPerson());
    assertNotNull(downloadedMwConfig.getEidasConfiguration().getOrganization());

    assertFalse(downloadedMwConfig.getEidConfiguration().getDvcaConfiguration().isEmpty());
    assertEquals(1, downloadedMwConfig.getEidConfiguration().getDvcaConfiguration().size());
    assertNotNull(downloadedMwConfig.getEidConfiguration().getTimerConfiguration());
    assertFalse(downloadedMwConfig.getEidConfiguration().getServiceProvider().isEmpty());
    assertEquals(1, downloadedMwConfig.getEidConfiguration().getServiceProvider().size());

    assertFalse(downloadedMwConfig.getKeyData().getCertificate().isEmpty());
    assertEquals(4, downloadedMwConfig.getKeyData().getCertificate().size());

    List<KeyStoreType> keyStores = downloadedMwConfig.getKeyData().getKeyStore();
    assertFalse(keyStores.isEmpty());
    assertEquals(3, keyStores.size());
    for ( KeyStoreType keyStore : keyStores )
    {
      assertNull(keyStore.getKeyStore());
      assertNull(keyStore.getPassword());
    }

    List<KeyPairType> keyPairs = downloadedMwConfig.getKeyData().getKeyPair();
    assertFalse(keyPairs.isEmpty());
    assertEquals(3, keyPairs.size());
    for ( KeyPairType keyPair : keyPairs )
    {
      assertNull(keyPair.getPassword());
    }

    assertNotNull(downloadedMwConfig.getSupportData());
    assertFalse(downloadedMwConfig.getSupportData().getKeyPairCertificates().isEmpty());
    assertEquals(3, downloadedMwConfig.getSupportData().getKeyPairCertificates().size());
  }

  @ParameterizedTest
  @ValueSource(strings = {ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.IMPORT_EXPORT_CONFIGURATION
                          + "/downloadWithoutPrivateKeys",
                          ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.IMPORT_EXPORT_CONFIGURATION + "/downloadWithPrivateKeys"})
  void testWhenNoConfigurationPresentThenMessageWithInfo(String path) throws Exception
  {
    HtmlPage configurationPageWithMessage = getConfigurationPage().getAnchorByHref(path).click();
    assertTrue(configurationPageWithMessage.asNormalizedText().contains("No configuration present!"));
    assertTrue(configurationService.getConfiguration().isEmpty());
  }

  private HtmlPage getConfigurationPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl(ContextPaths.IMPORT_EXPORT_CONFIGURATION));
    HtmlPage configurationPage = login(loginPage);
    assertTrue(configurationPage.getUrl().getPath().endsWith(ContextPaths.IMPORT_EXPORT_CONFIGURATION));
    return configurationPage;
  }
}
