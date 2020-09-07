/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.governikus.eumw.configuration.wizard.identifier.ApplicationPropertiesIdentifier;
import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.extern.slf4j.Slf4j;


/**
 * author Pascal Knueppel <br>
 * created at: 04.04.2018 - 23:58 <br>
 * <br>
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ApplicationPropertiesFormTest extends AbstractConfigFileTest
{

  /**
   * will return the fully quallified URL to the application properties based on the given configuration
   * directory in the test-resources
   *
   * @param configDir the configuration directory that holds the test-resources
   * @return the URL to the properties file
   */
  private URL getApplicationPropertiesFilePath(String configDir)
  {
    final String propertiesPath = CONFIGURATION_LOCATION + SLASH + configDir + SLASH
                                  + FileNames.APPLICATION_PROPERTIES.getFileName();
    URL propertiesUrl = getClass().getResource(propertiesPath);
    Assertions.assertNotNull(propertiesUrl,
                             FileNames.APPLICATION_PROPERTIES.getFileName() + " could not be found in "
                                            + "path '" + propertiesPath + "'");
    return propertiesUrl;
  }

  /**
   * this method will test if a given configuration has been read successfully and entered into the
   * application with the resources under {@link #CONFIG_DIR_SUCCESS} <br>
   * <br>
   * <b>NOTE:</b><br>
   * this test will also test reading the ssl-keystore given in the properties file. In order to do that we
   * will override the ssl-keystore properties in the file during the test and store it in another file that
   * will then be read for the test. This is done because we need absolute paths in the properties-file and to
   * have this test running on different operating systems we need to create these absolute paths in a dynamic
   * way.
   */
  @Test // NOPMD
  @DisplayName("read application.property file and find keystore")
  void testReadApplicationPropertiesFile()
  {
    final URL propertiesUrl = getApplicationPropertiesFilePath(CONFIG_DIR_SUCCESS);
    Properties applicationProperties = loadProperties(propertiesUrl);
    final String overriddenProperties = propertiesUrl.getFile() + "_overridden";
    final NameValuePair[] pairs = getApplicationKeystoreProperties();
    applicationProperties = overridePropertyInPropertiesFile(applicationProperties,
                                                             overriddenProperties,
                                                             pairs);

    ApplicationPropertiesForm applicationPropertiesForm = new ApplicationPropertiesForm();
    File overriddenPropertiesFile = new File(overriddenProperties);
    log.info("creating overridden properties file for test in: {}",
             overriddenPropertiesFile.getAbsolutePath());
    Assertions.assertTrue(applicationPropertiesForm.loadConfiguration(overriddenPropertiesFile),
                          "loading the configuration must return 'true'");

    // @formatter:off
    EQUAL_NULL_CHECK.accept(applicationPropertiesForm.getServerPort(),
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_PORT.getPropertyName()));
    Assertions.assertNotNull(applicationPropertiesForm.getServerSslKeystore(),
                             "server.ssl.keystore must exist");
    EQUAL_NULL_CHECK.accept(KeyStoreSupporter.KeyStoreType.JKS.name(),
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName()));
    EQUAL_NULL_CHECK.accept(KeyStoreSupporter.KeyStoreType.JKS.name(),
                            applicationPropertiesForm.getServerSslKeystore().getKeystore().getType());
    EQUAL_NULL_CHECK.accept(KEYSTORE_MASTER_PASSWORD,
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName()));
    EQUAL_NULL_CHECK.accept(KEYSTORE_MASTER_PASSWORD,
                            applicationPropertiesForm.getServerSslKeystore().getKeystorePassword());
    EQUAL_NULL_CHECK.accept(KEYSTORE_MASTER_PASSWORD,
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName()));
    EQUAL_NULL_CHECK.accept(KEYSTORE_MASTER_PASSWORD,
                            applicationPropertiesForm.getServerSslKeystore().getPrivateKeyPassword());
    EQUAL_NULL_CHECK.accept(KEYSTORE_ALIAS,
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName()));
    EQUAL_NULL_CHECK.accept(KEYSTORE_ALIAS, applicationPropertiesForm.getServerSslKeystore().getAlias());
    EQUAL_NULL_CHECK.accept(applicationPropertiesForm.getDatasourceUrl(),
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.DATASOURCE_URL.getPropertyName()));
    EQUAL_NULL_CHECK.accept(applicationPropertiesForm.getDatasourcePassword(),
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.DATASOURCE_PASSWORD.getPropertyName()));
    EQUAL_NULL_CHECK.accept(applicationPropertiesForm.getDatasourceUsername(),
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.DATASOURCE_USERNAME.getPropertyName()));
    EQUAL_NULL_CHECK.accept(applicationPropertiesForm.getAdminUsername(),
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.ADMIN_USERNAME.getPropertyName()));
    EQUAL_NULL_CHECK.accept(applicationPropertiesForm.getAdminPassword(),
                            applicationProperties.getProperty(ApplicationPropertiesIdentifier.ADMIN_PASSWORD.getPropertyName()));
    EQUAL_NULL_CHECK.accept(applicationPropertiesForm.getAdditionalProperties(),
                            "logging.level.foo.bar=ERROR");
    // @formatter:on
  }

  /**
   * this test will read the application properties file in {@link #CONFIG_DIR_SUCCESS},
   * {@link #CONFIG_DIR_EMPTY_VALUES}, {@link #CONFIG_DIR_FALSE_VALUES} and will show that the execution of
   * the code will not fail just because the SSL keystore cannot be found
   */
  @ParameterizedTest // NOPMD
  @ValueSource(strings = {CONFIG_DIR_SUCCESS, CONFIG_DIR_EMPTY_VALUES, CONFIG_DIR_FALSE_VALUES})
  @DisplayName("read application.property but do not find keystore")
  void testReadApplicationPropertiesFileMissingKeystore(String configDir)
  {
    final URL propertiesUrl = getApplicationPropertiesFilePath(configDir);
    Properties applicationProperties = loadProperties(propertiesUrl);
    ApplicationPropertiesForm applicationPropertiesForm = new ApplicationPropertiesForm();
    applicationPropertiesForm.loadConfiguration(new File(propertiesUrl.getFile()));

    // @formatter:off
    final String keystorePath = applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName())
                                                     .replace("file:", "");
    // @formatter:on
    Assertions.assertNotNull(keystorePath);
    Assertions.assertFalse(new File(keystorePath).exists(),
                           "keystore at path '" + keystorePath + "' should not exist");
    Assertions.assertNull(applicationPropertiesForm.getServerSslKeystore());
  }

  /**
   * this test will read the application properties file in {@link #CONFIG_DIR_EMPTY_VALUES} and will show
   * that the execution of the code will not fail if only empty values are read
   */
  @Test
  @DisplayName("read configuration file with empty values")
  void testReadApplicationPropertiesWithOnlyEmptyValues()
  {
    final URL propertiesUrl = getApplicationPropertiesFilePath(CONFIG_DIR_EMPTY_VALUES);
    Properties applicationProperties = loadProperties(propertiesUrl);
    ApplicationPropertiesForm applicationPropertiesForm = new ApplicationPropertiesForm();
    applicationPropertiesForm.loadConfiguration(new File(propertiesUrl.getFile()));

    // @formatter:off
    CHECK_IS_BLANK.accept(applicationPropertiesForm.getServerPort(),
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_PORT.getPropertyName()));
    Assertions.assertNull(applicationPropertiesForm.getServerSslKeystore());
    CHECK_IS_BLANK.accept(null,
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName()));
    CHECK_IS_BLANK.accept(null,
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName()));
    CHECK_IS_BLANK.accept(null,
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName()));
    CHECK_IS_BLANK.accept(null,
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName()));
    CHECK_IS_BLANK.accept(null,
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName()));
    CHECK_IS_BLANK.accept(applicationPropertiesForm.getDatasourceUrl(),
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.DATASOURCE_URL.getPropertyName()));
    CHECK_IS_BLANK.accept(applicationPropertiesForm.getDatasourceUsername(),
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.DATASOURCE_USERNAME.getPropertyName()));
    CHECK_IS_BLANK.accept(applicationPropertiesForm.getDatasourcePassword(),
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.DATASOURCE_PASSWORD.getPropertyName()));
    CHECK_IS_BLANK.accept(applicationPropertiesForm.getAdminUsername(),
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.ADMIN_USERNAME.getPropertyName()));
    CHECK_IS_BLANK.accept(applicationPropertiesForm.getAdminPassword(),
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.ADMIN_PASSWORD.getPropertyName()));
    CHECK_IS_BLANK.accept(applicationPropertiesForm.getLogFile(),
                          applicationProperties.getProperty(ApplicationPropertiesIdentifier.LOGGING_FILE.getPropertyName()));
    // @formatter:on
  }

  /**
   * this test will read the configuration and will find the keystore attributes are erroneous. This will not
   * result in an aborted application state but in an empty keystore that could just not be read which will
   * force the user to upload the keystore manually
   */
  @Test
  @DisplayName("read application.property file and find keystore with wrong attributes")
  void testReadApplicationPropertiesFileFalseValues()
  {
    final URL propertiesUrl = getApplicationPropertiesFilePath(CONFIG_DIR_FALSE_VALUES);
    Properties applicationProperties = loadProperties(propertiesUrl);
    final String overriddenProperties = propertiesUrl.getFile() + "_overridden";
    final NameValuePair[] pairs = getWrongApplicationKeystoreProperties();
    applicationProperties = overridePropertyInPropertiesFile(applicationProperties,
                                                             overriddenProperties,
                                                             pairs);

    ApplicationPropertiesForm applicationPropertiesForm = new ApplicationPropertiesForm();
    File overriddenPropertiesFile = new File(overriddenProperties);
    log.info("creating overridden properties file for test in: {}",
             overriddenPropertiesFile.getAbsolutePath());
    Assertions.assertTrue(applicationPropertiesForm.loadConfiguration(overriddenPropertiesFile),
                          "loading the configuration must return 'true'");

    // @formatter:off
    final String keystorePath = applicationProperties.getProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName())
                                                     .replace("file:", "");
    // @formatter:on
    Assertions.assertNotNull(keystorePath);
    Assertions.assertTrue(new File(keystorePath).exists(),
                          "keystore at path '" + keystorePath + "' must exist!");
    Assertions.assertNull(applicationPropertiesForm.getServerSslKeystore());
  }

  /**
   * this method will collect a bunch of properties that we will override in the properties file for the JUnit
   * test. <br>
   * we will override the properties because we need absolute paths for reading whats inside the properties.
   * And in order to have the test not failing on different operating systems we need to create the absolute
   * paths in the property-files dynamically
   *
   * @return the properties for the ssl-keystore in the application.properties-file
   */
  private NameValuePair[] getApplicationKeystoreProperties()
  {
    // @formatter:off
    return new NameValuePair[]{new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName(),
                                                 "file:" + getClass().getResource("/test-files/junit-test.jks")
                                                                     .getFile()),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName(),
                                                 KEYSTORE_MASTER_PASSWORD),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName(),
                                                 KEYSTORE_MASTER_PASSWORD),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName(),
                                                 KEYSTORE_ALIAS),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName(),
                                                 KeyStoreSupporter.KeyStoreType.JKS.name())};
    // @formatter:on
  }

  /**
   * this method will collect a bunch of properties that we will override in the properties file for the JUnit
   * test. <br>
   * we will override the properties because we need absolute paths for reading whats inside the properties.
   * And in order to have the test not failing on different operating systems we need to create the absolute
   * paths in the property-files dynamically<br>
   * <br>
   * <b>NOTE:</b><br>
   * the returned values here will have a false alias that is not present in the keystore that shall be
   * loaded. This must NOT result in an exception but in an empty keystore in the configuration in the end.
   *
   * @return the properties for the ssl-keystore in the application.properties-file
   */
  private NameValuePair[] getWrongApplicationKeystoreProperties()
  {
    final String falseAlias = "false-alias";
    // @formatter:off
    return new NameValuePair[]{new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName(),
                                                 "file:" + getClass().getResource("/test-files/junit-test.jks")
                                                                     .getFile()),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName(),
                                                 KEYSTORE_MASTER_PASSWORD),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName(),
                                                 KEYSTORE_MASTER_PASSWORD),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName(),
                                                 falseAlias),
                               new NameValuePair(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName(),
                                                 KeyStoreSupporter.KeyStoreType.JKS.name())};
    // @formatter:on
  }
}
