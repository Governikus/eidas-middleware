/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.WebAssert;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.configuration.wizard.web.ExposedReloadableResourceBundleMessageSource;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.PoseidasCoreConfigFormTest;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import lombok.extern.slf4j.Slf4j;


/**
 * test scenarios with multiple service providers
 *
 * @author prange
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("test different scenarions with multiple service providers")
public class MultipleServiceProviderTest extends ConfigWizardTestBase
{

  /**
   * The default SSLKeysID
   */
  private static final String DEFAULT_SSL_KEYS_ID = "default";

  /**
   * The validation message for an incorrect default service provider setting
   */
  private static final String INCORRECT_DEFAULT_SERVICEPROVIDER = "wizard.status.validation.incorrect.default.serviceprovider";

  /**
   * providerB
   */
  private static final String PROVIDER_B = "providerB";

  /**
   * Contains all resources from the property files
   */
  @Autowired
  ExposedReloadableResourceBundleMessageSource messageSource;

  /**
   * Test that it is possible to create a new config from scratch with two service providers
   */
  @Test
  public void testCreateTwoServiceProviders() throws IOException, UnrecoverableKeyException,
    CertificateException, NoSuchAlgorithmException, KeyStoreException
  {
    // start the user journey until the poseidas is configured
    HtmlPage startPage = getWebClient().getPage(getRequestUrl(ROOT_PATH));
    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPage(applicationPropertiesPage);
    HtmlPage eidasPropertiesPage = testPoseidasPage(poseidasPage);

    // add the second service provider and continue to save the config
    eidasPropertiesPage = addAnotherServiceProvider(eidasPropertiesPage);
    HtmlPage saveLocationPage = testEidasMiddlewarePropertiesPage(eidasPropertiesPage);
    setTextValue(saveLocationPage, "coreConfiguration-saveLocation", getTempDirectory());
    click(saveLocationPage, Button.SAVE);

    // check the number of service providers and the first service provider
    validateDefaultPoseidasData(2);

    // check the second service provider
    URL poseidasXmlUrl = Paths.get(getTempDirectory(), "POSeIDAS.xml").toUri().toURL();
    PoseidasCoreConfiguration poseidasCoreConfiguration = PoseidasCoreConfigFormTest.getPoseidasCoreConfiguration(poseidasXmlUrl);
    validateServiceProvider(DEFAULT_SSL_KEYS_ID,
                            poseidasCoreConfiguration.getServiceProvider().get(1),
                            "anotherServiceProvider",
                            "/test-files/ec-sign.p12",
                            "ec-sign");
  }

  /**
   * Test various validation errors regarding the service providers
   */
  @Test
  public void testValidationErrors() throws IOException
  {
    // start the user journey until the poseidas is configured
    HtmlPage startPage = getWebClient().getPage(getRequestUrl(ROOT_PATH));
    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPage(applicationPropertiesPage);

    poseidasPage = uploadCertificatesAndKeystores(poseidasPage, SERVER_CERT_NAME, CLIENT_KEYSTORE_NAME);
    // fill in the form for the common service provider data
    poseidasPage = setRadioButton(poseidasPage, DVCA_BUDRU_FIELD_ID);
    setTextValue(poseidasPage, SERVER_URL_FIELD_ID, SERVER_URL);
    setSelectValue(poseidasPage, BLACK_LIST_FIELD_ID, BLACKLIST_CERT_NAME);
    setSelectValue(poseidasPage, MASTER_LIST_FIELD_ID, MASTERLIST_CERT_NAME);
    setSelectValue(poseidasPage, DEFECT_LIST_FIELD_ID, DEFECTLIST_CERT_NAME);
    setSelectValue(poseidasPage, SERVER_CERTIFICATE_FIELD_ID, SERVER_CERT_NAME);

    // no service provider configured
    poseidasPage = click(poseidasPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(poseidasPage, getMessage("wizard.status.validation.missing.serviceprovider"));

    // cannot create empty service provider
    poseidasPage = click(poseidasPage, Button.UPLOAD_SERVICE_PROVIDER);
    assertValidationMessagePresent(poseidasPage,
                                   ENTITY_ID_FIELD_ID + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));

    // cannot create service provider without the client keystore
    setTextValue(poseidasPage, ENTITY_ID_FIELD_ID, "newEntity");
    poseidasPage = click(poseidasPage, Button.UPLOAD_SERVICE_PROVIDER);
    assertValidationMessagePresent(poseidasPage,
                                   CLIENT_KEYSTORE_FIELD_ID + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_KEYSTORE));

    // no public service provider set -> invalid
    setSelectValue(poseidasPage, CLIENT_KEYSTORE_FIELD_ID, CLIENT_KEYSTORE_NAME);
    poseidasPage = click(poseidasPage, Button.UPLOAD_SERVICE_PROVIDER);
    poseidasPage = click(poseidasPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(poseidasPage, getMessage(INCORRECT_DEFAULT_SERVICEPROVIDER));

    // valid
    setCheckboxValue(poseidasPage, "publicServiceProvider-0-publicServiceProvider", true);
    checkValidConfig(poseidasPage);

    // adding another public service provider -> invalid
    setTextValue(poseidasPage, ENTITY_ID_FIELD_ID, "anotherEntity");
    setSelectValue(poseidasPage, CLIENT_KEYSTORE_FIELD_ID, CLIENT_KEYSTORE_NAME);
    setCheckboxValue(poseidasPage,
                     "minimalServiceProviderForm-minimalServiceProviderForm.publicServiceProvider",
                     true);
    poseidasPage = click(poseidasPage, Button.UPLOAD_SERVICE_PROVIDER);
    poseidasPage = click(poseidasPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(poseidasPage, getMessage(INCORRECT_DEFAULT_SERVICEPROVIDER));

    // unselecting all public service provider -> invalid
    setCheckboxValue(poseidasPage, "publicServiceProvider-1-publicServiceProvider", false);
    setCheckboxValue(poseidasPage, "publicServiceProvider-0-publicServiceProvider", false);
    poseidasPage = click(poseidasPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(poseidasPage, getMessage(INCORRECT_DEFAULT_SERVICEPROVIDER));

    // selecting only the second public service provider
    setCheckboxValue(poseidasPage, "publicServiceProvider-1-publicServiceProvider", true);
    checkValidConfig(poseidasPage);
  }

  /**
   * Load a config with 2 service providers, change nothing and save them
   */
  @Test
  public void testLoadMultipleServiceProviders() throws IOException, URISyntaxException,
    UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException
  {
    // prepare the configuration that should be read
    Path configDir = prepareConfigDir(getClass().getResource("/test-configurations/full-config"));

    // perform the user journey until the config is saved
    HtmlPage startPage = getWebClient().getPage(getRequestUrl(ROOT_PATH));
    setTextValue(startPage, "configDirectory.configDirectory", configDir.toString());
    HtmlPage uploadPage = click(startPage, Button.NEXT_PAGE);
    HtmlPage applicationPage = click(uploadPage, Button.NEXT_PAGE);
    HtmlPage poseidasPage = click(applicationPage, Button.NEXT_PAGE);
    HtmlPage middlewarePage = click(poseidasPage, Button.NEXT_PAGE);
    HtmlPage savePage = click(middlewarePage, Button.NEXT_PAGE);
    setTextValue(savePage,
                 "coreConfiguration-saveLocation",
                 configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString());
    HtmlPage successPage = click(savePage, Button.SAVE);
    WebAssert.assertTextPresent(successPage,
                                "The files have been created at: "
                                             + configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString());

    // Check that both service providers are still correctly configured
    URL poseidasXmlUrl = Paths.get(configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString(), "POSeIDAS.xml")
                              .toUri()
                              .toURL();
    PoseidasCoreConfiguration poseidasCoreConfiguration = PoseidasCoreConfigFormTest.getPoseidasCoreConfiguration(poseidasXmlUrl);
    Assertions.assertEquals(2,
                            poseidasCoreConfiguration.getServiceProvider().size(),
                            "Two service providers expected");
    validateServiceProvider(DEFAULT_SSL_KEYS_ID,
                            poseidasCoreConfiguration.getServiceProvider().get(0),
                            "providerA",
                            "/test-configurations/full-config/providerA.p12",
                            "providerA");
    validateServiceProvider(DEFAULT_SSL_KEYS_ID,
                            poseidasCoreConfiguration.getServiceProvider().get(1),
                            PROVIDER_B,
                            "/test-configurations/full-config/providerB.p12",
                            PROVIDER_B);
  }

  /**
   * Read a config wih two service providers, remove one and save the config
   */
  @Test
  public void removeServiceProvider() throws IOException, URISyntaxException, UnrecoverableKeyException,
    CertificateException, NoSuchAlgorithmException, KeyStoreException
  {
    // prepare the configuration that should be read
    Path configDir = prepareConfigDir(getClass().getResource("/test-configurations/full-config"));

    // start the user journey
    HtmlPage startPage = getWebClient().getPage(getRequestUrl(ROOT_PATH));
    setTextValue(startPage, "configDirectory.configDirectory", configDir.toString());
    HtmlPage uploadPage = click(startPage, Button.NEXT_PAGE);
    HtmlPage applicationPage = click(uploadPage, Button.NEXT_PAGE);
    HtmlPage poseidasPage = click(applicationPage, Button.NEXT_PAGE);

    // delete the first service provider
    poseidasPage = click(poseidasPage, "service-provider-0-delete-button");
    poseidasPage = click(poseidasPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(poseidasPage, getMessage(INCORRECT_DEFAULT_SERVICEPROVIDER));
    setCheckboxValue(poseidasPage, "publicServiceProvider-0-publicServiceProvider", true);

    // continue the journey until the config is saved
    HtmlPage middlewarePage = click(poseidasPage, Button.NEXT_PAGE);
    HtmlPage savePage = click(middlewarePage, Button.NEXT_PAGE);
    setTextValue(savePage,
                 "coreConfiguration-saveLocation",
                 configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString());
    HtmlPage successPage = click(savePage, Button.SAVE);
    WebAssert.assertTextPresent(successPage,
                                "The files have been created at: "
                                             + configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString());

    // read the saved config and check that only one service provider is present
    URL poseidasXmlUrl = Paths.get(configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString(), "POSeIDAS.xml")
                              .toUri()
                              .toURL();
    PoseidasCoreConfiguration poseidasCoreConfiguration = PoseidasCoreConfigFormTest.getPoseidasCoreConfiguration(poseidasXmlUrl);
    Assertions.assertEquals(1,
                            poseidasCoreConfiguration.getServiceProvider().size(),
                            "One service providers expected");
    validateServiceProvider(DEFAULT_SSL_KEYS_ID,
                            poseidasCoreConfiguration.getServiceProvider().get(0),
                            PROVIDER_B,
                            "/test-configurations/full-config/providerB.p12",
                            PROVIDER_B);
  }

  /**
   * Click on next page, check that the middleware configuration page is shown and then go to the previous
   * page again
   *
   * @param poseidasPage The current poseidas config page
   */
  private void checkValidConfig(HtmlPage poseidasPage) throws IOException
  {
    HtmlPage propertiesPage = click(poseidasPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(propertiesPage, getMessage("middleware.configuration"));
    HtmlPage previousPage = click(poseidasPage, Button.PREVIOUS_PAGE);
    WebAssert.assertTextPresent(previousPage, getMessage("core.configuration"));
  }

  /**
   * Add a second service provider
   *
   * @param eidasPropertiesPage The config page for the eidas middleware settings
   * @return The config page for the eidas middleware settings after the service provider was added
   */
  private HtmlPage addAnotherServiceProvider(HtmlPage eidasPropertiesPage) throws IOException
  {
    HtmlPage poseidasPage = click(eidasPropertiesPage, Button.PREVIOUS_PAGE);

    poseidasPage = uploadKeystore(poseidasPage,
                                  "secondServiceProvider",
                                  "ec-sign",
                                  DEFAULT_KEYSTORE_PASSWORD,
                                  DEFAULT_KEYSTORE_PASSWORD,
                                  "/test-files/ec-sign.p12");

    setTextValue(poseidasPage,
                 "minimalServiceProviderForm-minimalServiceProviderForm.entityID",
                 "anotherServiceProvider");
    setSelectValue(poseidasPage,
                   "poseidasConfig.minimalServiceProviderForm.sslKeysForm.clientKeyForm",
                   "secondServiceProvider");
    setCheckboxValue(poseidasPage,
                     "minimalServiceProviderForm-minimalServiceProviderForm.publicServiceProvider",
                     false);
    poseidasPage = click(poseidasPage, Button.UPLOAD_SERVICE_PROVIDER);

    HtmlPage nextPage = click(poseidasPage, Button.NEXT_PAGE);
    assertNotNull(nextPage.getElementById("eidasmiddlewareProperties.metadataSignatureCertificate"),
                  "eIDAS middleware configuration page should be present.");

    return nextPage;
  }
}
