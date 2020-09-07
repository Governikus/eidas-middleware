/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

import javax.xml.bind.JAXBException;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.WebAssert;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.configuration.wizard.identifier.ApplicationPropertiesIdentifier;
import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.identifier.MiddlewarePropertiesIdentifier;
import de.governikus.eumw.configuration.wizard.web.ExposedReloadableResourceBundleMessageSource;
import lombok.extern.slf4j.Slf4j;


/**
 * test the complete user journey
 *
 * @author prange
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("test the complete user journey")
@ActiveProfiles("test")
class CompleteUserJourneyTest extends ConfigWizardTestBase // NOPMD
{

  /**
   * Contains all resources from the property files
   */
  @Autowired
  ExposedReloadableResourceBundleMessageSource messageSource;

  /**
   * Test the complete user journey without a previous configuration. Afterwards the configuration is loaded
   * and new metadata is uploaded to check that the old metadata is deleted.
   */
  @Test
  void testCompleteUserJourney() throws IOException, CertificateException, UnrecoverableKeyException,
    KeyStoreException, NoSuchAlgorithmException
  {
    HtmlPage startPage = getWebClient().getPage(getRequestUrl("/"));

    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPage(applicationPropertiesPage);
    HtmlPage eidasPropertiesPage = testPoseidasPage(poseidasPage);

    HtmlPage currentEidasPropertiesPage = testPreviousPage(eidasPropertiesPage);

    HtmlPage saveLocationPage = testEidasMiddlewarePropertiesPage(currentEidasPropertiesPage);

    setTextValue(saveLocationPage, "coreConfiguration-saveLocation", getTempDirectory());

    click(saveLocationPage, Button.SAVE);

    validateApplicationProperties();
    validateDefaultPoseidasData(1);
    validateEidasMiddlewareProperties();

    uploadNewMetadata();
  }


  /**
   * Test the complete user journey with hsm configuration and without a previous configuration.
   */
  @Test
  void testCompleteUserJourneyWithHSM() throws IOException, CertificateException, UnrecoverableKeyException,
    KeyStoreException, NoSuchAlgorithmException
  {

    HtmlPage startPage = getWebClient().getPage(getRequestUrl("/"));

    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPageWithHSM(applicationPropertiesPage);
    HtmlPage eidasPropertiesPage = testPoseidasPageWithHSM(poseidasPage);

    HtmlPage currentEidasPropertiesPage = testPreviousPage(eidasPropertiesPage);

    HtmlPage saveLocationPage = testEidasMiddlewarePropertiesPageWithHSM(currentEidasPropertiesPage);

    setTextValue(saveLocationPage, "coreConfiguration-saveLocation", getTempDirectory());

    click(saveLocationPage, Button.SAVE);

    validateApplicationPropertiesWithHSM();
    validateDefaultPoseidasDataWithHSM(1);
    validateEidasMiddlewarePropertiesWithHSM();
  }

  /**
   * Test that SERVER_URL is added to eidasmiddleware.properties when loading a previous configuration without
   * this property key.
   */
  @Test
  void testConfigWithoutServerURL() throws IOException, JAXBException, CertificateException,
    UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    createConfig();

    // Remove SERVER_URL from eidasmiddleware.properties
    List<String> properties = FileUtils.readLines(Paths.get(getTempDirectory(), "eidasmiddleware.properties")
                                                       .toFile(),
                                                  StandardCharsets.UTF_8);
    properties = properties.stream()
                           .filter(property -> !property.startsWith("SERVER_URL"))
                           .collect(Collectors.toList());

    FileUtils.writeLines(Paths.get(getTempDirectory(), "eidasmiddleware.properties").toFile(), properties);


    // Clear cookies to start from the first page
    getWebClient().getCookieManager().clearCookies();
    HtmlPage currentPage = getWebClient().getPage(getRequestUrl("/"));

    setTextValue(currentPage, "configDirectory.configDirectory", getTempDirectory());
    // go to upload existing config
    currentPage = click(currentPage, Button.NEXT_PAGE);
    // go to application.properties
    currentPage = click(currentPage, Button.NEXT_PAGE);
    // go to POSeIDAS.xml
    currentPage = click(currentPage, Button.NEXT_PAGE);
    // go to eidasmiddleware.properties
    currentPage = click(currentPage, Button.NEXT_PAGE);

    // go to save page
    currentPage = click(currentPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(currentPage, "Save location");
    click(currentPage, Button.SAVE);

    validateApplicationProperties();
    validateDefaultPoseidasData(1);
    validateEidasMiddlewareProperties();
  }

  private void createConfig() throws IOException
  {
    HtmlPage startPage = getWebClient().getPage(getRequestUrl("/"));

    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPage(applicationPropertiesPage);
    HtmlPage eidasPropertiesPage = testPoseidasPage(poseidasPage);

    HtmlPage saveLocationPage = testEidasMiddlewarePropertiesPage(eidasPropertiesPage);

    setTextValue(saveLocationPage, "coreConfiguration-saveLocation", getTempDirectory());

    click(saveLocationPage, Button.SAVE);
  }

  private void uploadNewMetadata() throws IOException
  {
    // check that there is only one metadata file
    Path path = Paths.get(getTempDirectory(), "serviceprovider-metadata");
    assertEquals(1,
                 path.toFile().listFiles().length,
                 "There must be exactly one service provider metadata file");

    // Clear cookies to start from the first page
    getWebClient().getCookieManager().clearCookies();
    HtmlPage currentPage = getWebClient().getPage(getRequestUrl("/"));

    setTextValue(currentPage, "configDirectory.configDirectory", getTempDirectory());
    // go to upload existing config
    currentPage = click(currentPage, Button.NEXT_PAGE);
    // go to application.properties
    currentPage = click(currentPage, Button.NEXT_PAGE);
    // go to POSeIDAS.xml
    currentPage = click(currentPage, Button.NEXT_PAGE);
    // go to eidasmiddleware.properties
    currentPage = click(currentPage, Button.NEXT_PAGE);

    // Upload new metadata
    currentPage = click(currentPage, "metadata-0-button");
    String newMetadataContent = "<newMetadata/>";
    Path newMetadataFile = Files.write(Paths.get(getTempDirectory(), "newMetadata.xml"),
                                       newMetadataContent.getBytes(StandardCharsets.UTF_8));

    HtmlFileInput metadataFileInput = (HtmlFileInput)currentPage.getElementById("eidasmiddlewareProperties.uploadedFile");
    metadataFileInput.setFiles(newMetadataFile.toFile());
    currentPage = click(currentPage, "metadata-upload-button");

    // go to save page
    currentPage = click(currentPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(currentPage, "Save location");
    click(currentPage, Button.SAVE);

    assertEquals(1,
                 path.toFile().listFiles().length,
                 "There must be exactly one service provider metadata file");
    assertEquals(new String(Files.readAllBytes(path.resolveSibling("newMetadata.xml"))),
                 newMetadataContent,
                 "New content expected");
  }

  /**
   * check if the entered data in the application.properties file is correct
   *
   * @throws IOException
   */
  private void validateApplicationProperties() throws IOException
  {
    // Assert that the files are created
    assertTrue(Files.exists(Paths.get(getTempDirectory(), "ssl.jks")), "File ssl.jks is missing.");

    Properties applicationProperties = loadProperties(FileNames.APPLICATION_PROPERTIES.getFileName());

    // Assert that the application.properties contains the correct values
    assertEquals("8080",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_PORT.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("11111",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_INTERFACE_PORT.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("file:" + Paths.get(getTempDirectory(), "ssl.jks").toString().replace("\\", "/"),
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("ssl",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals(DEFAULT_KEYSTORE_PASSWORD,
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals(DEFAULT_KEYSTORE_PASSWORD,
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("JKS",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("databaseURL",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_URL.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("databaseName",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_USERNAME.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("databasePassword",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_PASSWORD.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("poseidasUsername",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_USERNAME.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertTrue(BCrypt.checkpw("poseidasPassword",
                              (String)applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_PASSWORD.getPropertyName())),
               VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("logFilePath",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.LOGGING_FILE.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertEquals("DEBUG",
                 applicationProperties.remove("logging.level.de.governikus"),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("ERROR",
                 applicationProperties.remove("logging.level.foo.bar"),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertNotNull(applicationProperties.remove(ApplicationPropertiesIdentifier.HSM_TYPE.getPropertyName()),
                  VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertEquals(0, applicationProperties.size(), "There are more properties available than expected");
  }

  private void validateApplicationPropertiesWithHSM() throws IOException
  {
    // Assert that the files are created
    assertTrue(Files.exists(Paths.get(getTempDirectory(), "ssl.jks")), "File ssl.jks is missing.");

    Properties applicationProperties = loadProperties(FileNames.APPLICATION_PROPERTIES.getFileName());

    // Assert that the application.properties contains the correct values
    assertEquals("8080",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_PORT.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("11111",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_INTERFACE_PORT.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("file:" + Paths.get(getTempDirectory(), "ssl.jks").toString().replace("\\", "/"),
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("ssl",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals(DEFAULT_KEYSTORE_PASSWORD,
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals(DEFAULT_KEYSTORE_PASSWORD,
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("JKS",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("databaseURL",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_URL.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("databaseName",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_USERNAME.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("databasePassword",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_PASSWORD.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("poseidasUsername",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_USERNAME.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertTrue(BCrypt.checkpw("poseidasPassword",
                              (String)applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_PASSWORD.getPropertyName())),
               VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("logFilePath",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.LOGGING_FILE.getPropertyName()),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertEquals("DEBUG",
                 applicationProperties.remove("logging.level.de.governikus"),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);
    assertEquals("ERROR",
                 applicationProperties.remove("logging.level.foo.bar"),
                 VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertNotNull(applicationProperties.remove(ApplicationPropertiesIdentifier.HSM_TYPE.getPropertyName()),
                  VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertNotNull(applicationProperties.remove(ApplicationPropertiesIdentifier.HSM_KEYS_DELETE.getPropertyName()),
                  VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertNotNull(applicationProperties.remove(ApplicationPropertiesIdentifier.HSM_KEYS_ARCHIVE.getPropertyName()),
                  VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertNotNull(applicationProperties.remove(ApplicationPropertiesIdentifier.PKCS11_SUN_CONFIG_PROVIDER_FILE_PATH.getPropertyName()),
                  VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertNotNull(applicationProperties.remove(ApplicationPropertiesIdentifier.PKCS11_HSM_PASSWORD.getPropertyName()),
                  VALIDATE_APPLICATION_PROPERTIES_MESSAGE);

    assertEquals(0, applicationProperties.size(), "There are more properties available than expected");
  }

  /**
   * check if the entered data in the eidasmiddleware.properties file is correct
   */
  private void validateEidasMiddlewareProperties() throws IOException
  {
    // Assert that the files are created
    assertTrue(Files.exists(Paths.get(getTempDirectory(), SERVICEPROVIDER_METADATA_FOLDER)),
               "Folder serviceprovider-metadata is missing.");
    assertTrue(Files.exists(Paths.get(getTempDirectory(), SERVICEPROVIDER_METADATA_FOLDER, "metadata.xml")),
               "File metadata.xml is missing.");
    assertTrue(Files.exists(Paths.get(getTempDirectory(), "signatureKeystore.jks")),
               "File signatureKeystore.jks is missing.");
    assertTrue(Files.exists(Paths.get(getTempDirectory(), "decryptionKeystore.p12")),
               "File decryptionKeystore.p12 is missing.");
    assertTrue(Files.exists(Paths.get(getTempDirectory(), "signatureCertificate.crt")),
               "File signatureCertificate.crt is missing.");

    Properties eidasProperties = loadProperties(FileNames.MIDDLEWARE_PROPERTIES.getFileName());

    // Assert that the eidasmiddleware.properties contains the correct values
    assertEquals(SERVER_URL,
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.SERVER_URL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(SERVICEPROVIDER_ENTITY_ID,
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ENTITYID_INT.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(Paths.get(getTempDirectory(), SERVICEPROVIDER_METADATA_FOLDER).toString().replace("\\", "/"),
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(Paths.get(getTempDirectory(), "signatureCertificate.crt").toString().replace("\\", "/"),
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_METADATA_SIGNATURE_CERT.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(Paths.get(getTempDirectory(), "decryptionKeystore.p12").toString().replace("\\", "/"),
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_KEY.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("middleware_decrypt",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_ALIAS.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(DEFAULT_KEYSTORE_PASSWORD,
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_PIN.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(Paths.get(getTempDirectory(), "signatureKeystore.jks").toString().replace("\\", "/"),
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_KEY.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("middleware_sign",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_ALIAS.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(DEFAULT_KEYSTORE_PASSWORD,
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_SIGN_PIN.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("DE",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.COUNTRYCODE.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("givenname",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_GIVENNAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("surname",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_SURNAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("company",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_COMPANY.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("tel",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_TEL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("email",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_EMAIL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("displayname",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_DISPLAY_NAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("name",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_NAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("url",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_URL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("lang",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_LANG.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
  }

  private void validateEidasMiddlewarePropertiesWithHSM() throws IOException
  {

    // Assert that the files are created
    assertTrue(Files.exists(Paths.get(getTempDirectory(), SERVICEPROVIDER_METADATA_FOLDER)),
               "Folder serviceprovider-metadata is missing.");
    assertTrue(Files.exists(Paths.get(getTempDirectory(), SERVICEPROVIDER_METADATA_FOLDER, "metadata.xml")),
               "File metadata.xml is missing.");
    assertTrue(Files.exists(Paths.get(getTempDirectory(), "decryptionKeystore.p12")),
               "File decryptionKeystore.p12 is missing.");
    assertTrue(Files.exists(Paths.get(getTempDirectory(), "signatureCertificate.crt")),
               "File signatureCertificate.crt is missing.");

    Properties eidasProperties = loadProperties(FileNames.MIDDLEWARE_PROPERTIES.getFileName());

    // Assert that the eidasmiddleware.properties contains the correct values
    assertEquals(SERVER_URL,
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.SERVER_URL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(SERVICEPROVIDER_ENTITY_ID,
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ENTITYID_INT.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(Paths.get(getTempDirectory(), SERVICEPROVIDER_METADATA_FOLDER).toString().replace("\\", "/"),
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_CONFIG_FOLDER.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(Paths.get(getTempDirectory(), "signatureCertificate.crt").toString().replace("\\", "/"),
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.SERVICE_PROVIDER_METADATA_SIGNATURE_CERT.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(Paths.get(getTempDirectory(), "decryptionKeystore.p12").toString().replace("\\", "/"),
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_KEY.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("middleware_decrypt",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_ALIAS.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals(DEFAULT_KEYSTORE_PASSWORD,
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.MIDDLEWARE_CRYPT_PIN.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("DE",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.COUNTRYCODE.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("givenname",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_GIVENNAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("surname",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_SURNAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("company",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_COMPANY.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("tel",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_TEL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("email",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.CONTACT_PERSON_EMAIL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("displayname",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_DISPLAY_NAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("name",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_NAME.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("url",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_URL.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
    assertEquals("lang",
                 eidasProperties.getProperty(MiddlewarePropertiesIdentifier.ORGANIZATION_LANG.name()),
                 VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE);
  }

  private Properties loadProperties(final String fileName) throws IOException, FileNotFoundException
  {
    Properties eidasProperties = new Properties();
    try (FileInputStream eidasInputStream = new FileInputStream(Paths.get(getTempDirectory(), fileName)
                                                                     .toString()))
    {
      eidasProperties.load(eidasInputStream);
    }
    return eidasProperties;
  }

  private HtmlPage testPreviousPage(HtmlPage currentPage) throws IOException
  {
    assertNotNull(currentPage.getElementById("eidasmiddlewareProperties.metadataSignatureCertificate"),
                  "eIDAS middleware configuration page should be present.");
    HtmlPage previousPage = click(currentPage, Button.PREVIOUS_PAGE);
    assertNotNull(previousPage.getElementById("coreConfig-coreConfig.serverUrl"),
                  "POSeIDAS configuration page should be present.");
    HtmlPage nextPage = click(previousPage, Button.NEXT_PAGE);
    assertNotNull(nextPage.getElementById("eidasmiddlewareProperties.metadataSignatureCertificate"),
                  "eIDAS middleware configuration page should be present.");
    return nextPage;
  }

  /**
   * this test will fail to upload a certificate
   */
  @Test
  void failToUploadCertificate() throws IOException
  {
    final String certName = "certificate-certificateName";
    final String certFile = "certificate-certificateFile";
    final String errorSuffix = ERROR_SUFFIX;

    HtmlPage uploadCertificatePage = getWebClient().getPage(getRequestUrl("/"));

    // upload nothing
    HtmlPage nothingUploadedPage = uploadCertificate(uploadCertificatePage, BLANK, BLANK);
    assertValidationMessagePresent(nothingUploadedPage,
                                   certName + errorSuffix,
                                   getMessage(KEY_VALIDATE_UPLOAD_NAME));
    assertValidationMessagePresent(nothingUploadedPage,
                                   certFile + errorSuffix,
                                   getMessage("wizard.status.validation.upload.file")
                                                           + "could not read certificate for empty certificate bytes");

    // upload certificate without name
    HtmlPage nameMissingPage = uploadCertificate(uploadCertificatePage, BLANK, "/test-files/test.cer");
    assertValidationMessagePresent(nameMissingPage,
                                   certName + errorSuffix,
                                   getMessage(KEY_VALIDATE_UPLOAD_NAME));
  }

  /**
   * this test will fail to upload a keystore
   */
  @Test
  void failToUploadKeystore() throws IOException
  {
    final String keystoreNameErrorFieldId = "keystore-keystoreName-error";
    final String keystoreAliasErrorFieldId = "keystore-alias-error";
    final String keystoreFileErrorFieldId = "keystore-keystoreFile-error";
    final String keystorePath = "/test-files/junit-test.jks";

    HtmlPage uploadKeystorePage = getWebClient().getPage(getRequestUrl("/"));

    // upload nothing
    HtmlPage fileMissing = uploadKeystore(uploadKeystorePage, BLANK, BLANK, BLANK, BLANK, BLANK);
    assertValidationMessagePresent(fileMissing,
                                   keystoreNameErrorFieldId,
                                   getMessage(KEY_VALIDATE_UPLOAD_NAME));
    assertValidationMessagePresent(fileMissing,
                                   keystoreAliasErrorFieldId,
                                   getMessage(KEY_VALIDATE_UPLOAD_ALIAS));
    assertValidationMessagePresent(fileMissing,
                                   keystoreFileErrorFieldId,
                                   getMessage("wizard.status.validation.upload.file"));

    // upload without name
    HtmlPage blankEntries = uploadKeystore(uploadKeystorePage, BLANK, BLANK, BLANK, BLANK, keystorePath);
    assertValidationMessagePresent(blankEntries,
                                   keystoreNameErrorFieldId,
                                   getMessage(KEY_VALIDATE_UPLOAD_NAME));
    assertValidationMessagePresent(blankEntries,
                                   keystoreAliasErrorFieldId,
                                   getMessage(KEY_VALIDATE_UPLOAD_ALIAS));
  }
}
