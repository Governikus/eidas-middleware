/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model;


import java.io.File;
import java.net.URL;
import java.util.Properties;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.identifier.MiddlewarePropertiesIdentifier;
import lombok.extern.slf4j.Slf4j;


/**
 * author Pascal Knueppel <br>
 * created at: 05.04.2018 - 00:10 <br>
 * <br>
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class EidasmiddlewarePropertiesFormTest extends AbstractConfigFileTest
{

  /**
   * will return the fully quallified URL to the middleware properties based on the given configuration
   * directory in the test-resources
   *
   * @param configDir the configuration directory that holds the test-resources
   * @return the URL to the properties file
   */
  private URL getEidasMiddlewarePropertiesFilePath(String configDir)
  {
    final String propertiesPath = CONFIGURATION_LOCATION + SLASH + configDir + SLASH
                                  + FileNames.MIDDLEWARE_PROPERTIES.getFileName();
    URL propertiesUrl = getClass().getResource(propertiesPath);
    Assertions.assertNotNull(propertiesUrl,
                             FileNames.MIDDLEWARE_PROPERTIES.getFileName() + " could not be found in "
                                            + "path '" + propertiesPath + "'");
    return propertiesUrl;
  }

  /**
   * this test will read the properties file in the given configuration directories and will overridde the
   * keystore entries within the properties in order to get it tested that the
   * {@link EidasmiddlewarePropertiesForm#loadConfiguration(File)} method will load the keystore if it is
   * found which must work on different operating systems for the JUnit test. And since the paths are
   * necessary to be absolute paths we need to ensure that the paths are created dynamically
   *
   * @param configDir the current configuration directory that should be read
   */
  @ParameterizedTest // NOPMD
  @ValueSource(strings = {CONFIG_DIR_SUCCESS, CONFIG_DIR_FALSE_VALUES})
  public void testReadEidasMiddlewarePropertiesFile(String configDir)
  {
    URL middlewarePropertiesUrl = getEidasMiddlewarePropertiesFilePath(configDir);
    Properties middlewareProperties = loadProperties(middlewarePropertiesUrl);
    final String tmpPropertiesFilePath = middlewarePropertiesUrl.getFile() + "_overridden";
    Properties overriddenProperties = overridePropertyInPropertiesFile(middlewareProperties,
                                                                       tmpPropertiesFilePath,
                                                                       getEidasMiddlewareProperties());
    EidasmiddlewarePropertiesForm eidasmiddlewarePropertiesForm = new EidasmiddlewarePropertiesForm();
    File overriddenPropertiesFile = new File(tmpPropertiesFilePath);
    Assertions.assertTrue(overriddenPropertiesFile.exists(),
                          "file at location '" + overriddenPropertiesFile.getAbsolutePath()
                                                             + "' must exist!");
    Assertions.assertTrue(eidasmiddlewarePropertiesForm.loadConfiguration(overriddenPropertiesFile),
                          "loading the configuration must return true on configuration directory: " + configDir);
    // @formatter:off
    final String serviceProviderConfigFolder = "/opt/application/config/euconfigs";
    EQUAL_NULL_CHECK.accept(serviceProviderConfigFolder,
                          overriddenProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name()));

    final String metadataSignatureCertPath = overriddenProperties.getProperty(
                                      MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_METADATA_SIGNATURE_CERT.name());
    Assertions.assertNotNull(eidasmiddlewarePropertiesForm.getMetadataSignatureCertificate(),
                            "the certificate in path '" + metadataSignatureCertPath
                              + "' does exist and must be loaded");

    Assertions.assertNotNull(eidasmiddlewarePropertiesForm.getMiddlewareSignKeystore());
    final String signAlias = overriddenProperties.getProperty(
                                                        MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_ALIAS.name());
    EQUAL_NULL_CHECK.accept(KEYSTORE_ALIAS, signAlias);
    EQUAL_NULL_CHECK.accept(signAlias, eidasmiddlewarePropertiesForm.getMiddlewareSignKeystore().getAlias());

    final String signPin = overriddenProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_PIN.name());
    EQUAL_NULL_CHECK.accept(KEYSTORE_MASTER_PASSWORD, signPin);
    EQUAL_NULL_CHECK.accept(signPin, eidasmiddlewarePropertiesForm.getMiddlewareSignKeystore().getKeystorePassword());
    EQUAL_NULL_CHECK.accept(signPin, eidasmiddlewarePropertiesForm.getMiddlewareSignKeystore().getPrivateKeyPassword());

    Assertions.assertNotNull(eidasmiddlewarePropertiesForm.getMiddlewareCryptKeystore());
    final String cryptAlias = overriddenProperties.getProperty(
                                                        MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_ALIAS.name());
    EQUAL_NULL_CHECK.accept(KEYSTORE_ALIAS, cryptAlias);
    EQUAL_NULL_CHECK.accept(cryptAlias, eidasmiddlewarePropertiesForm.getMiddlewareCryptKeystore().getAlias());

    final String cryptPin = overriddenProperties.getProperty(
                                                        MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_PIN.name());
    EQUAL_NULL_CHECK.accept(KEYSTORE_MASTER_PASSWORD, cryptPin);
    EQUAL_NULL_CHECK.accept(cryptPin, eidasmiddlewarePropertiesForm.getMiddlewareCryptKeystore().getKeystorePassword());
    EQUAL_NULL_CHECK.accept(cryptPin, eidasmiddlewarePropertiesForm.getMiddlewareCryptKeystore().getPrivateKeyPassword());

    final String entityIdInt = "providerA";
    EQUAL_NULL_CHECK.accept(entityIdInt,
                            overriddenProperties.getProperty(MiddlewarePropertiesIdentifier.ENTITYID_INT.name()));
    EQUAL_NULL_CHECK.accept(entityIdInt,
                            eidasmiddlewarePropertiesForm.getEntityIdInt());

    final String serverURL = "https://localhost:8443";
    EQUAL_NULL_CHECK.accept(serverURL,
                            overriddenProperties.getProperty(MiddlewarePropertiesIdentifier.SERVER_URL.name()));
    EQUAL_NULL_CHECK.accept(serverURL,
                            eidasmiddlewarePropertiesForm.getServerURL());
    checkContactDetails(overriddenProperties, eidasmiddlewarePropertiesForm);
    // @formatter:on
  }

  /**
   * this test will read the middleware.properties in {@link #CONFIG_DIR_EMPTY_VALUES} and will check that the empty
   * values won't cause any problems when reading the configuration
   */
  @Test
  public void testReadConfigurationWithEmptyValues()
  {
    URL eidasMiddlewarePropertiesUrl = getEidasMiddlewarePropertiesFilePath(CONFIG_DIR_EMPTY_VALUES);
    Properties eidasMiddlewareProperties = loadProperties(eidasMiddlewarePropertiesUrl);
    EidasmiddlewarePropertiesForm eidasmiddlewarePropertiesForm = new EidasmiddlewarePropertiesForm();
    File eidasMiddlewarePropertiesFile = new File(eidasMiddlewarePropertiesUrl.getFile());
    Assertions.assertTrue(eidasMiddlewarePropertiesFile.exists(),
                          "file at location '" + eidasMiddlewarePropertiesFile.getAbsolutePath()
                                                                  + "' must exist!");
    // @formatter:off
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getServiceProviderMetadataPath(),
                          eidasMiddlewareProperties.getProperty(
                            MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name()));
    Assertions.assertNull(eidasmiddlewarePropertiesForm.getMetadataSignatureCertificate());
    CHECK_IS_BLANK.accept(null,
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_METADATA_SIGNATURE_CERT.name()));

    Assertions.assertNull(eidasmiddlewarePropertiesForm.getMiddlewareCryptKeystore());
    CHECK_IS_BLANK.accept(null,
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_KEY.name()));
    CHECK_IS_BLANK.accept(null,
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_PIN.name()));
    CHECK_IS_BLANK.accept(null,
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_ALIAS.name()));

    Assertions.assertNull(eidasmiddlewarePropertiesForm.getMiddlewareSignKeystore());
    CHECK_IS_BLANK.accept(null,
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_KEY.name()));
    CHECK_IS_BLANK.accept(null,
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_PIN.name()));
    CHECK_IS_BLANK.accept(null,
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_ALIAS.name()));

    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getEntityIdInt(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.ENTITYID_INT.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getCountryCode(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.COUNTRYCODE.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getContactPersonCompany(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.CONTACT_PERSON_COMPANY.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getContactPersonEmail(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.CONTACT_PERSON_EMAIL.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getContactPersonGivenname(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.CONTACT_PERSON_GIVENNAME.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getContactPersonSurname(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.CONTACT_PERSON_SURNAME.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getContactPersonTel(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.CONTACT_PERSON_TEL.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getOrganizationDisplayName(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.ORGANIZATION_DISPLAY_NAME.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getOrganizationName(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.ORGANIZATION_NAME.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getOrganizationUrl(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.ORGANIZATION_URL.name()));
    CHECK_IS_BLANK.accept(eidasmiddlewarePropertiesForm.getOrganizationLang(),
                          eidasMiddlewareProperties.getProperty(
                                    MiddlewarePropertiesIdentifier.ORGANIZATION_LANG.name()));
    // @formatter:on
  }

  /**
   * will check that the contact details in the eidas-middleware properties have the correct values for
   * {@link #CONFIG_DIR_SUCCESS} and for {@link #CONFIG_DIR_FALSE_VALUES}
   *
   * @param eidasProperties the properties containing the contact person values
   * @param eidasmiddlewarePropertiesForm the form for the view that has loaded the temporary overridden
   *          properties file
   */
  private void checkContactDetails(Properties eidasProperties,
                                   EidasmiddlewarePropertiesForm eidasmiddlewarePropertiesForm)
  {
    // @formatter:off
    final String countryCode = "DE";
    EQUAL_NULL_CHECK.accept(countryCode,
                            eidasProperties.getProperty(MiddlewarePropertiesIdentifier.COUNTRYCODE.name()));
    EQUAL_NULL_CHECK.accept(countryCode,
                            eidasmiddlewarePropertiesForm.getCountryCode());
    final String contactPersonCompany = "Governikus KG";
    EQUAL_NULL_CHECK.accept(contactPersonCompany,
                            eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_COMPANY.name()));
    EQUAL_NULL_CHECK.accept(contactPersonCompany,
                            eidasmiddlewarePropertiesForm.getContactPersonCompany());
    final String contactPersonEmail = "max.mustermann@governikus.de";
    EQUAL_NULL_CHECK.accept(contactPersonEmail,
                            eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_EMAIL.name()));
    EQUAL_NULL_CHECK.accept(contactPersonEmail,
                            eidasmiddlewarePropertiesForm.getContactPersonEmail());
    final String contactPersonGivenname = "Max";
    EQUAL_NULL_CHECK.accept(contactPersonGivenname,
                          eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_GIVENNAME.name()));
    EQUAL_NULL_CHECK.accept(contactPersonGivenname,
                            eidasmiddlewarePropertiesForm.getContactPersonGivenname());
    final String contactPersonSurname = "Mustermann";
    EQUAL_NULL_CHECK.accept(contactPersonSurname,
                            eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_SURNAME.name()));
    EQUAL_NULL_CHECK.accept(contactPersonSurname,
                            eidasmiddlewarePropertiesForm.getContactPersonSurname());
    final String contactPersonPhone = "123456789";
    EQUAL_NULL_CHECK.accept(contactPersonPhone,
                            eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_TEL.name()));
    EQUAL_NULL_CHECK.accept(contactPersonPhone,
                            eidasmiddlewarePropertiesForm.getContactPersonTel());
    final String organizationDisplayname = "Governikus KG";
    EQUAL_NULL_CHECK.accept(organizationDisplayname,
                        eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_DISPLAY_NAME.name()));
    EQUAL_NULL_CHECK.accept(organizationDisplayname,
                            eidasmiddlewarePropertiesForm.getOrganizationDisplayName());
    final String organizationName = "Bremen";
    EQUAL_NULL_CHECK.accept(organizationName,
                        eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_NAME.name()));
    EQUAL_NULL_CHECK.accept(organizationName,
                            eidasmiddlewarePropertiesForm.getOrganizationName());
    final String organizationUrl = "www.bremen.de";
    EQUAL_NULL_CHECK.accept(organizationUrl,
                        eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_URL.name()));
    EQUAL_NULL_CHECK.accept(organizationUrl,
                            eidasmiddlewarePropertiesForm.getOrganizationUrl());
    final String organizationLanguage = "German";
    EQUAL_NULL_CHECK.accept(organizationLanguage,
                        eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_LANG.name()));
    EQUAL_NULL_CHECK.accept(organizationLanguage,
                            eidasmiddlewarePropertiesForm.getOrganizationLang());
    // @formatter:on
  }

  /**
   * this method gets some properties for the eidas-middleware.properties to puth them into a temporary
   * properties file that can than be used. This is done to override the keystore and certificate locations to
   * absolute paths which is different on any operating system.
   *
   * @return the name value pairs to override to have a system independent reliable test
   */
  private NameValuePair[] getEidasMiddlewareProperties()
  {
    // @formatter:off
    return new NameValuePair[]
    {
      new NameValuePair(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_METADATA_SIGNATURE_CERT.name(),
                        getClass().getResource("/test-files/serviceProviderMetadataSign.cer").getFile()),
      new NameValuePair(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_KEY.name(),
                        getClass().getResource("/test-files/junit-test.jks").getFile()),
      new NameValuePair(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_ALIAS.name(),
                        KEYSTORE_ALIAS),
      new NameValuePair(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_PIN.name(),
                        KEYSTORE_MASTER_PASSWORD),
      new NameValuePair(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_KEY.name(),
                        getClass().getResource("/test-files/junit-test.jks").getFile()),
      new NameValuePair(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_ALIAS.name(),
                        KEYSTORE_ALIAS),
      new NameValuePair(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_PIN.name(),
                        KEYSTORE_MASTER_PASSWORD),
    };
    // @formatter:on
  }
}
