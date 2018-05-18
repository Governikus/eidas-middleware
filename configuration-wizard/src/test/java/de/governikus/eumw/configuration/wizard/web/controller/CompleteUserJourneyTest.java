/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import javax.xml.bind.JAXBException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlRadioButtonInput;
import com.gargoylesoftware.htmlunit.html.HtmlSelect;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;

import de.governikus.eumw.configuration.wizard.identifier.ApplicationPropertiesIdentifier;
import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.identifier.MiddlewarePropertiesIdentifier;
import de.governikus.eumw.configuration.wizard.web.ExposedReloadableResourceBundleMessageSource;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.PoseidasCoreConfigForm;
import de.governikus.eumw.poseidas.config.schema.EPAConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.KeyStoreSupporter.KeyStoreType;
import de.governikus.eumw.utils.xml.XmlHelper;
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
public class CompleteUserJourneyTest extends AbstractWebTest // NOPMD
{

  /**
   * Contains all resources from the property files
   */
  @Autowired
  ExposedReloadableResourceBundleMessageSource messageSource;

  /**
   * field id for success message if a certificate was successfully uploaded
   */
  private static final String CERTIFICATE_UPLOAD_SUCCESS = "certificateUploadSuccess";

  /**
   * field id for success message if a key store was successfully uploaded
   */
  private static final String KEYSTORE_UPLOAD_SUCCESS = "keystoreUploadSuccess";

  /**
   * message key to successful upload message
   */
  private static final String KEY_UPLOAD_SUCCESS = "wizard.status.upload.successful";

  /**
   * message key to validation message if field entry is blank
   */
  private static final String KEY_VALIDATE_BLANK = "wizard.status.validation.blank";

  /**
   * message key to validation message if certificate is not selected
   */
  private static final String KEY_VALIDATE_CERTIFICATE = "wizard.status.validation.certificate";

  /**
   * message key to validation message if keystore is not selected
   */
  private static final String KEY_VALIDATE_KEYSTORE = "wizard.status.validation.keystore";

  /**
   * message key to validation message if name for keystore or certificate is missing
   */
  private static final String KEY_VALIDATE_UPLOAD_NAME = "wizard.status.validation.upload.name";

  /**
   * message key to validation message if alias for keystore is missing
   */
  private static final String KEY_VALIDATE_UPLOAD_ALIAS = "wizard.status.validation.upload.alias";

  /**
   * junit test assertion when the validation of the created application properties failed
   */
  private static final String VALIDATE_APPLICATION_PROPERTIES_MESSAGE = "The created application.properties file is not correct.";

  /**
   * junit test assertion when the validation of the created application properties failed
   */
  private static final String VALIDATE_POSEIDAS_XML_MESSAGE = "The created poseidas.xml file is not correct.";

  /**
   * junit test assertion when the validation of the created application properties failed
   */
  private static final String VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE = "The created eidasmiddleware.properties file is not correct.";

  /**
   * name of the folder containing the metadata.xml
   */
  private static final String SERVICEPROVIDER_METADATA_FOLDER = "serviceprovider-metadata";

  /**
   * the service provider entity id used in the poseidas.xml and the eidasmiddleware.properties
   */
  private static final String SERVICEPROVIDER_ENTITY_ID = "myEntityID";

  /**
   * password for accessing the keystores in the resources
   */
  private static final String DEFAULT_KEYSTORE_PASSWORD = "123456";

  /**
   * suffix for error field ids
   */
  private static final String ERROR_SUFFIX = "-error";

  /**
   * blank text entry
   */
  private static final String BLANK = "";

  /**
   * all possible buttons for identification
   */
  private enum Button
  {
    NEXT_PAGE, PREVIOUS_PAGE, SAVE, UPLOAD_CERTIFICATE, UPLOAD_KEYSTORE
  }

  @Test
  public void completeUserJourney() throws IOException, JAXBException, CertificateException,
    UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
  {
    HtmlPage startPage = getWebClient().getPage(getRequestUrl("/"));

    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPage(applicationPropertiesPage);
    HtmlPage eidasPropertiesPage = testPoseidasPage(poseidasPage);

    // test previous page button
    assertNotNull(eidasPropertiesPage.getElementById("eidasmiddlewareProperties.metadataSignatureCertificate"),
                  "eIDAS middleware configuration page should be present.");
    HtmlPage previousPage = click(eidasPropertiesPage, Button.PREVIOUS_PAGE);
    assertNotNull(previousPage.getElementById("coreConfig-coreConfig.serverUrl"),
                  "POSeIDAS configuration page should be present.");
    eidasPropertiesPage = click(previousPage, Button.NEXT_PAGE);
    assertNotNull(eidasPropertiesPage.getElementById("eidasmiddlewareProperties.metadataSignatureCertificate"),
                  "eIDAS middleware configuration page should be present.");

    HtmlPage saveLocationPage = testEidasMiddlewarePropertiesPage(eidasPropertiesPage);

    setTextValue(saveLocationPage, "coreConfiguration-saveLocation", getTempDirectory());

    click(saveLocationPage, Button.SAVE);

    validateApplicationProperties();
    validatePoseidasData();
    validateEidasMiddlewareProperties();
  }

  /**
   * test the page where one can enter the configuration directory
   */
  private HtmlPage testConfigDirectoryPage(HtmlPage startPage) throws IOException
  {
    assertNotNull(startPage.getElementById("configDirectory.configDirectory"),
                  "The test should be on page 1 but isn't.");
    return click(startPage, Button.NEXT_PAGE);

  }

  /**
   * test the page where one can upload its old configurations
   */
  private HtmlPage testUploadPage(HtmlPage uploadOldConfigurationPage) throws IOException
  {
    String wrongPageErrorMessage = "Upload of existing configurations not possible. This is not the correct page.";
    assertNotNull(uploadOldConfigurationPage.getElementById("poseidasConfig.poseidasConfigXmlFile"),
                  wrongPageErrorMessage);
    assertNotNull(uploadOldConfigurationPage.getElementById("applicationProperties.applicationPropertiesFile"),
                  wrongPageErrorMessage);
    assertNotNull(uploadOldConfigurationPage.getElementById("eidasmiddlewareProperties.eidasPropertiesFile"),
                  wrongPageErrorMessage);

    return click(uploadOldConfigurationPage, Button.NEXT_PAGE);
  }


  /**
   * test the application property page
   */
  private HtmlPage testApplicationPropertiesPage(HtmlPage currentPage) throws IOException
  {
    final String serverPortFieldId = "applicationProperties-serverPort";
    final String selectKeystoreFieldId = "applicationProperties.serverSslKeystore";
    final String dbUrlFieldId = "applicationProperties-datasourceUrl";
    final String dbUsernameFieldId = "applicationProperties-datasourceUsername";
    final String dbPasswordFieldId = "applicationProperties-datasourcePassword";
    final String adminUsernameFieldId = "applicationProperties-adminUsername";
    final String adminPasswordFieldId = "applicationProperties-adminPassword";
    final String logFileFieldId = "applicationProperties-logFile";
    final String additionalPropertiesFieldId = "applicationProperties-additionalProperties";

    // upload necessary ssl keystore
    final String ssl = "ssl";
    HtmlPage currentPageWithKeystore = uploadKeystore(currentPage,
                                                      ssl,
                                                      ssl,
                                                      DEFAULT_KEYSTORE_PASSWORD,
                                                      DEFAULT_KEYSTORE_PASSWORD,
                                                      "/test-files/ssl.jks");
    assertTextPresent(currentPageWithKeystore, KEYSTORE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));

    // click next without any entries
    HtmlPage pageBlankError = click(currentPageWithKeystore, Button.NEXT_PAGE);
    assertTextPresent(pageBlankError, serverPortFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));
    assertTextPresent(pageBlankError, "serverSslKeystore-error", getMessage(KEY_VALIDATE_KEYSTORE));
    assertTextPresent(pageBlankError, dbUrlFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));
    assertTextPresent(pageBlankError, dbUsernameFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));
    assertTextPresent(pageBlankError, dbPasswordFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));
    assertTextPresent(pageBlankError, adminUsernameFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));
    assertTextPresent(pageBlankError, adminPasswordFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));

    // fill in invalid server port
    setTextValue(currentPageWithKeystore, serverPortFieldId, getMessage("server.port"));
    HtmlPage pageNoNumberError = click(currentPageWithKeystore, Button.NEXT_PAGE);
    assertTextPresent(pageNoNumberError,
                      serverPortFieldId + ERROR_SUFFIX,
                      getMessage("wizard.status.validation.number"));

    // fill in form
    setTextValue(currentPageWithKeystore, serverPortFieldId, "8080");
    setSelectValue(currentPageWithKeystore, selectKeystoreFieldId, ssl);
    setTextValue(currentPageWithKeystore, dbUrlFieldId, "databaseURL");
    setTextValue(currentPageWithKeystore, dbUsernameFieldId, "databaseName");
    setPasswordValue(currentPageWithKeystore, dbPasswordFieldId, "databasePassword");
    setTextValue(currentPageWithKeystore, adminUsernameFieldId, "poseidasUsername");
    setPasswordValue(currentPageWithKeystore, adminPasswordFieldId, "poseidasPassword");
    setTextValue(currentPageWithKeystore, logFileFieldId, "logFilePath");
    setTextValue(currentPageWithKeystore, additionalPropertiesFieldId, "logging.level.de.governikus=DEBUG\nlogging.level.foo.bar=ERROR");

    return click(currentPageWithKeystore, Button.NEXT_PAGE);
  }

  /**
   * test the poseidas page
   */
  private HtmlPage testPoseidasPage(HtmlPage currentPage) throws IOException
  {
    final String serverUrlFieldId = "coreConfig-coreConfig.serverUrl";
    final String entityIdFieldId = "serviceProvider-serviceProvider.entityID";
    final String blackListFieldId = "poseidasConfig.serviceProvider.blackListTrustAnchor";
    final String masterListFieldId = "poseidasConfig.serviceProvider.masterListTrustAnchor";
    final String defectListFieldId = "poseidasConfig.serviceProvider.defectListTrustAnchor";
    final String serverCertificateFieldId = "poseidasConfig.serviceProvider.sslKeysForm.serverCertificate";
    final String clientKeystoreFieldId = "poseidasConfig.serviceProvider.sslKeysForm.clientKeyForm";
    final String dvcaBudruFieldId = "poseidasConfig.serviceProvider.policyID1";

    // upload necessary certificates and keystore for poseidas page
    final String blacklist = "blacklist";
    final String defectlist = "defectlist";
    final String masterlist = "masterlist";
    final String serverCert = "serverCert";
    final String clientKeystore = "clientKeystore";
    HtmlPage blacklistUploaded = uploadCertificate(currentPage, blacklist, "/test-files/blacklist.pem");
    assertTextPresent(blacklistUploaded, CERTIFICATE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage defectlistUploaded = uploadCertificate(blacklistUploaded,
                                                    defectlist,
                                                    "/test-files/defectlist.pem");
    assertTextPresent(defectlistUploaded, CERTIFICATE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage masterlistUploaded = uploadCertificate(defectlistUploaded,
                                                    masterlist,
                                                    "/test-files/masterlist.pem");
    assertTextPresent(masterlistUploaded, CERTIFICATE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage serverCertUploaded = uploadCertificate(masterlistUploaded,
                                                    serverCert,
                                                    "/test-files/dvca_server_cert.pem");
    assertTextPresent(serverCertUploaded, CERTIFICATE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage allFilesUploaded = uploadKeystore(serverCertUploaded,
                                               clientKeystore,
                                               "dvca_client",
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               "/test-files/dvca_client.jks");
    assertTextPresent(allFilesUploaded, KEYSTORE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));

    // fill in invalid url, leave other entries empty
    setTextValue(allFilesUploaded, serverUrlFieldId, "no valid url");
    HtmlPage emptyPage = click(allFilesUploaded, Button.NEXT_PAGE);
    assertTextPresent(emptyPage, serverUrlFieldId + ERROR_SUFFIX, getMessage("wizard.status.validation.url"));
    assertTextPresent(emptyPage, entityIdFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));
    assertTextPresent(emptyPage, "blackListTrustAnchor-error", getMessage(KEY_VALIDATE_CERTIFICATE));
    assertTextPresent(emptyPage, "masterListTrustAnchor-error", getMessage(KEY_VALIDATE_CERTIFICATE));
    assertTextPresent(emptyPage, "defectListTrustAnchor-error", getMessage(KEY_VALIDATE_CERTIFICATE));
    assertTextPresent(emptyPage, "serverCertificate-error", getMessage(KEY_VALIDATE_CERTIFICATE));
    assertTextPresent(emptyPage, "clientKeyForm-error", getMessage(KEY_VALIDATE_KEYSTORE));
    assertTextPresent(emptyPage, "policyID-error", getMessage("wizard.status.validation.dvca.missing"));

    // fill in form
    HtmlPage selectedRadioButtonPage = setRadioButton(allFilesUploaded, dvcaBudruFieldId);
    setTextValue(selectedRadioButtonPage, serverUrlFieldId, "http://myhost:8443");
    setTextValue(selectedRadioButtonPage, entityIdFieldId, SERVICEPROVIDER_ENTITY_ID);
    setSelectValue(selectedRadioButtonPage, blackListFieldId, blacklist);
    setSelectValue(selectedRadioButtonPage, masterListFieldId, masterlist);
    setSelectValue(selectedRadioButtonPage, defectListFieldId, defectlist);
    setSelectValue(selectedRadioButtonPage, serverCertificateFieldId, serverCert);
    setSelectValue(selectedRadioButtonPage, clientKeystoreFieldId, clientKeystore);

    return click(allFilesUploaded, Button.NEXT_PAGE);
  }

  /**
   * test the eidas middleware properties page
   */
  private HtmlPage testEidasMiddlewarePropertiesPage(HtmlPage currentPage) throws IOException
  {
    final String metadataFileFieldId = "serviceProviderMetadataFile";
    final String signatureCertificateFieldId = "metadataSignatureCertificate";
    final String signatureKeystoreFieldId = "middlewareSignKeystore";
    final String cryptKeystoreFieldId = "middlewareCryptKeystore";
    final String countryFieldId = "serviceProvider-countryCode";

    final String companyFieldId = "serviceProvider-contactPersonCompany";
    final String emailFieldId = "serviceProvider-contactPersonEmail";
    final String givennameFieldId = "serviceProvider-contactPersonGivenname";
    final String surnameFieldId = "serviceProvider-contactPersonSurname";
    final String telephoneFieldId = "serviceProvider-contactPersonTel";
    final String organisationFieldId = "serviceProvider-organizationDisplayName";
    final String organisiationNameFieldId = "serviceProvider-organizationName";
    final String organisationUrlFieldId = "serviceProvider-organizationUrl";
    final String organisationLangFieldId = "serviceProvider-organizationLang";

    // fill in blank values, leave rest empty
    HtmlPage emptyPage = click(currentPage, Button.NEXT_PAGE);
    assertTextPresent(emptyPage,
                      metadataFileFieldId + ERROR_SUFFIX,
                      getMessage("wizard.status.validation.file.empty"));
    assertTextPresent(emptyPage,
                      signatureCertificateFieldId + ERROR_SUFFIX,
                      getMessage(KEY_VALIDATE_CERTIFICATE));
    assertTextPresent(emptyPage, signatureKeystoreFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_KEYSTORE));
    assertTextPresent(emptyPage, cryptKeystoreFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_KEYSTORE));
    assertTextPresent(emptyPage, countryFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));

    // upload necessary certificates and keystore for middleware page
    final String signatureCertificate = "signatureCertificate";
    final String signatureKeystore = "signatureKeystore";
    final String decryptionKeystore = "decryptionKeystore";
    HtmlPage uploadedMetaCert = uploadCertificate(currentPage,
                                                  signatureCertificate,
                                                  "/test-files/serviceProviderMetadataSign.cer");
    assertTextPresent(uploadedMetaCert, CERTIFICATE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage uploadedSignKeystore = uploadKeystore(uploadedMetaCert,
                                                   signatureKeystore,
                                                   "middleware_sign",
                                                   DEFAULT_KEYSTORE_PASSWORD,
                                                   DEFAULT_KEYSTORE_PASSWORD,
                                                   "/test-files/middleware_sign.jks");
    assertTextPresent(uploadedSignKeystore, KEYSTORE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage allFilesUploaded = uploadKeystore(uploadedSignKeystore,
                                               decryptionKeystore,
                                               "middleware_decrypt",
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               "/test-files/middleware_decrypt.p12");
    assertTextPresent(allFilesUploaded, KEYSTORE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));

    // fill in form
    HtmlFileInput metadataFileInput = (HtmlFileInput)allFilesUploaded.getElementById(metadataFileFieldId);
    File metadataFile = new File(getClass().getResource("/test-files/metadata.xml").toString());
    metadataFileInput.setFiles(metadataFile);
    setSelectValue(allFilesUploaded,
                   "eidasmiddlewareProperties.metadataSignatureCertificate",
                   signatureCertificate);
    setSelectValue(allFilesUploaded, "eidasmiddlewareProperties.middlewareSignKeystore", signatureKeystore);
    setSelectValue(allFilesUploaded, "eidasmiddlewareProperties.middlewareCryptKeystore", decryptionKeystore);
    setTextValue(allFilesUploaded, "serviceProvider-countryCode", "DE");
    setTextValue(allFilesUploaded, "serviceProvider-contactPersonCompany", "company");
    setTextValue(allFilesUploaded, "serviceProvider-contactPersonEmail", "email");
    setTextValue(allFilesUploaded, "serviceProvider-contactPersonGivenname", "givenname");
    setTextValue(allFilesUploaded, "serviceProvider-contactPersonSurname", "surname");
    setTextValue(allFilesUploaded, "serviceProvider-contactPersonTel", "tel");
    setTextValue(allFilesUploaded, "serviceProvider-organizationDisplayName", "displayname");
    setTextValue(allFilesUploaded, "serviceProvider-organizationName", "name");
    setTextValue(allFilesUploaded, "serviceProvider-organizationUrl", "url");
    setTextValue(allFilesUploaded, "serviceProvider-organizationLang", "lang");

    return click(allFilesUploaded, Button.NEXT_PAGE);
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

    // Assert that the application.properties contains the correct values
    Properties applicationProperties = new Properties();
    try (
      FileInputStream applicationInputStream = new FileInputStream(Paths.get(getTempDirectory(),
                                                                             FileNames.APPLICATION_PROPERTIES.getFileName())
                                                                        .toString()))
    {
      applicationProperties.load(applicationInputStream);
    }

    assertEquals("8080",
                 applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_PORT.getPropertyName()),
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

    assertEquals(0, applicationProperties.size(), "There are more properties available than expected");
  }

  /**
   * check if the entered data in the poseidas.xml is correct
   *
   * @throws IOException
   * @throws JAXBException
   * @throws CertificateException
   * @throws KeyStoreException
   * @throws NoSuchAlgorithmException
   * @throws UnrecoverableKeyException
   */
  private void validatePoseidasData() throws IOException, JAXBException, CertificateException, // NOPMD
    KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
  {
    final String sslKeysId = "default";

    String xmlSource;
    try (FileInputStream inputStream = new FileInputStream(Paths
                                                                .get(getTempDirectory(),
                                                                     FileNames.POSEIDAS_XML.getFileName())
                                                                .toString()))
    {
      xmlSource = IOUtils.toString(inputStream, Charset.defaultCharset());
    }
    PoseidasCoreConfiguration poseidasConfig = XmlHelper.unmarshal(xmlSource,
                                                                   PoseidasCoreConfiguration.class);

    assertEquals("http://myhost:8443/eidas-middleware",
                 poseidasConfig.getServerUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertTrue(poseidasConfig.isSessionManagerUsesDatabase(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.SESSION_MAX_PENDING_REQUESTS,
                 poseidasConfig.getSessionMaxPendingRequests(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.CERTIFICATE_WARNING_MARGIN,
                 poseidasConfig.getCertificateWarningMargin(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.LENGTH,
                 poseidasConfig.getTimerConfiguration().getCertRenewal().getLength(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.UNIT,
                 poseidasConfig.getTimerConfiguration().getCertRenewal().getUnit(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.LENGTH,
                 poseidasConfig.getTimerConfiguration().getBlacklistRenewal().getLength(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.UNIT,
                 poseidasConfig.getTimerConfiguration().getBlacklistRenewal().getUnit(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.LENGTH,
                 poseidasConfig.getTimerConfiguration().getMasterAndDefectListRenewal().getLength(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.UNIT,
                 poseidasConfig.getTimerConfiguration().getMasterAndDefectListRenewal().getUnit(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);

    List<ServiceProviderType> spList = poseidasConfig.getServiceProvider();
    assertEquals(1, spList.size(), VALIDATE_POSEIDAS_XML_MESSAGE); // NOPMD
    ServiceProviderType serviceProvider = spList.get(0);

    assertEquals(SERVICEPROVIDER_ENTITY_ID, serviceProvider.getEntityID(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertTrue(serviceProvider.isEnabled(), VALIDATE_POSEIDAS_XML_MESSAGE);

    EPAConnectorConfigurationType epaConnectorConfigurationType = serviceProvider.getEPAConnectorConfiguration();
    assertTrue(epaConnectorConfigurationType.isUpdateCVC(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(SERVICEPROVIDER_ENTITY_ID,
                 epaConnectorConfigurationType.getCVCRefID(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("http://myhost:8443/eidas-middleware/paosreceiver",
                 epaConnectorConfigurationType.getPaosReceiverURL(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    final Integer hoursToRefresh = 48;
    assertEquals(hoursToRefresh, // NOPMD
                 epaConnectorConfigurationType.getHoursRefreshCVCBeforeExpires(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);

    PkiConnectorConfigurationType pkiConnectorConfigurationType = epaConnectorConfigurationType.getPkiConnectorConfiguration();
    assertEqualCertificates(getClass().getResource("/test-files/blacklist.pem"),
                            pkiConnectorConfigurationType.getBlackListTrustAnchor());
    assertEqualCertificates(getClass().getResource("/test-files/defectlist.pem"),
                            pkiConnectorConfigurationType.getDefectListTrustAnchor());
    assertEqualCertificates(getClass().getResource("/test-files/masterlist.pem"),
                            pkiConnectorConfigurationType.getMasterListTrustAnchor());
    assertEquals("budru",
                 pkiConnectorConfigurationType.getPolicyImplementationId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getTerminalAuthService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://berca-ps.d-trust.net/ps/dvca-at",
                 pkiConnectorConfigurationType.getTerminalAuthService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getRestrictedIdService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://berca-ps.d-trust.net/ps/dvsd_v2",
                 pkiConnectorConfigurationType.getRestrictedIdService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getPassiveAuthService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://berca-ps.d-trust.net/ps/scs",
                 pkiConnectorConfigurationType.getPassiveAuthService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getDvcaCertDescriptionService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://berca-ps.d-trust.net/ps/dvca-at-cert-desc",
                 pkiConnectorConfigurationType.getDvcaCertDescriptionService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);

    List<SslKeysType> sslKeysList = pkiConnectorConfigurationType.getSslKeys();
    assertEquals(1, sslKeysList.size(), VALIDATE_POSEIDAS_XML_MESSAGE); // NOPMD
    assertEquals(sslKeysId, sslKeysList.get(0).getId(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEqualCertificates(getClass().getResource("/test-files/dvca_server_cert.pem"),
                            sslKeysList.get(0).getServerCertificate());

    byte[] keystoreBytes = IOUtils.toByteArray(getClass().getResource("/test-files/dvca_client.jks"));
    KeyStore keystore = KeyStoreSupporter.readKeyStore(keystoreBytes,
                                                       KeyStoreType.JKS,
                                                       DEFAULT_KEYSTORE_PASSWORD);

    assertArrayEquals(keystore.getCertificate("dvca_client").getEncoded(),
                      sslKeysList.get(0).getClientCertificate().get(0),
                      VALIDATE_POSEIDAS_XML_MESSAGE);

    assertArrayEquals(keystore.getKey("dvca_client", DEFAULT_KEYSTORE_PASSWORD.toCharArray()).getEncoded(),
                      sslKeysList.get(0).getClientKey(),
                      VALIDATE_POSEIDAS_XML_MESSAGE);

    // assert not needed values are empty
    assertNull(poseidasConfig.getSignatureCertWebService(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertNull(poseidasConfig.getSignatureKeyWebService(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertNull(serviceProvider.getSignatureCert(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertNull(serviceProvider.getSignatureCert2(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertNull(epaConnectorConfigurationType.getClientSSLCert(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertNull(epaConnectorConfigurationType.getClientSSLCert2(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertNull(epaConnectorConfigurationType.getCommunicationErrorURL(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertNull(pkiConnectorConfigurationType.getAutentServerUrl(), VALIDATE_POSEIDAS_XML_MESSAGE);
  }

  /**
   * Read the certificate from the test resources and compare it to the certificate from the configuration
   * file
   *
   * @param url The URL to the certificate file from the test resources
   * @param certificateFromConfig the certificate from the configuration file
   */
  private void assertEqualCertificates(URL url, byte[] certificateFromConfig)
    throws CertificateException, IOException
  {
    X509Certificate cert = KeyReader.readX509Certificate(IOUtils.toByteArray(url));
    assertArrayEquals(cert.getEncoded(), certificateFromConfig, VALIDATE_POSEIDAS_XML_MESSAGE);
  }

  /**
   * check if the entered data in the eidasmiddleware.properties file is correct
   *
   * @throws IOException
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

    // Assert that the eidasmiddleware.properties contains the correct values
    Properties eidasProperties = new Properties();
    try (
      FileInputStream eidasInputStream = new FileInputStream(Paths.get(getTempDirectory(),
                                                                       FileNames.MIDDLEWARE_PROPERTIES.getFileName())
                                                                  .toString()))
    {

      eidasProperties.load(eidasInputStream);
    }

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


  /**
   * this test will fail to upload a certificate
   */
  @Test
  public void failToUploadCertificate() throws IOException
  {
    final String certName = "certificate-certificateName";
    final String certFile = "certificate-certificateFile";
    final String errorSuffix = ERROR_SUFFIX;

    HtmlPage uploadCertificatePage = getWebClient().getPage(getRequestUrl("/"));

    // upload nothing
    HtmlPage nothingUploadedPage = uploadCertificate(uploadCertificatePage, BLANK, BLANK);
    assertTextPresent(nothingUploadedPage, certName + errorSuffix, getMessage(KEY_VALIDATE_UPLOAD_NAME));
    assertTextPresent(nothingUploadedPage,
                      certFile + errorSuffix,
                      getMessage("wizard.status.validation.upload.file")
                                              + "could not read certificate for empty certificate bytes");

    // upload certificate without name
    HtmlPage nameMissingPage = uploadCertificate(uploadCertificatePage, BLANK, "/test-files/test.cer");
    assertTextPresent(nameMissingPage, certName + errorSuffix, getMessage(KEY_VALIDATE_UPLOAD_NAME));
  }

  /**
   * this test will fail to upload a keystore
   */
  @Test
  public void failToUploadKeystore() throws IOException
  {
    final String keystoreNameErrorFieldId = "keystore-keystoreName-error";
    final String keystoreAliasErrorFieldId = "keystore-alias-error";
    final String keystoreFileErrorFieldId = "keystore-keystoreFile-error";
    final String keystorePath = "/test-files/junit-test.jks";

    HtmlPage uploadKeystorePage = getWebClient().getPage(getRequestUrl("/"));

    // upload nothing
    HtmlPage fileMissing = uploadKeystore(uploadKeystorePage, BLANK, BLANK, BLANK, BLANK, BLANK);
    assertTextPresent(fileMissing, keystoreNameErrorFieldId, getMessage(KEY_VALIDATE_UPLOAD_NAME));
    assertTextPresent(fileMissing, keystoreAliasErrorFieldId, getMessage(KEY_VALIDATE_UPLOAD_ALIAS));
    assertTextPresent(fileMissing,
                      keystoreFileErrorFieldId,
                      getMessage("wizard.status.validation.upload.file"));

    // upload without name
    HtmlPage blankEntries = uploadKeystore(uploadKeystorePage, BLANK, BLANK, BLANK, BLANK, keystorePath);
    assertTextPresent(blankEntries, keystoreNameErrorFieldId, getMessage(KEY_VALIDATE_UPLOAD_NAME));
    assertTextPresent(blankEntries, keystoreAliasErrorFieldId, getMessage(KEY_VALIDATE_UPLOAD_ALIAS));
  }

  /**
   * Upload a certificate
   *
   * @param currentPage
   * @param name the name that should be inserted in the form
   * @param stringPath the path to the file in the test resources, if blank nothing is uploaded
   * @return the updated page with the loaded certificate or with the error message
   */
  private HtmlPage uploadCertificate(HtmlPage currentPage, String name, String stringPath)
  {
    final String certificateNameFieldId = "certificate-certificateName";
    final String certificateFileFieldId = "certificate-certificateFile";

    HtmlFileInput certificateFileInput = (HtmlFileInput)currentPage.getElementById(certificateFileFieldId);

    setTextValue(currentPage, certificateNameFieldId, name);
    if (StringUtils.isNotBlank(stringPath))
    {
      File certificateFile = new File(getClass().getResource(stringPath).toString());
      certificateFileInput.setFiles(certificateFile);
    }

    try
    {
      return click(currentPage, Button.UPLOAD_CERTIFICATE);
    }
    catch (IOException e)
    {
      log.error("Cannot upload certificate", e);
      fail("Cannot upload certificate");
      return currentPage;
    }
  }

  /**
   * Upload a keystore
   *
   * @param currentPage
   * @param name the name that should be inserted in the form
   * @param alias the alias of the key in the key store
   * @param keystorePassword the password of the key store
   * @param keyPassword the password of the key
   * @param stringPath the path to the file in the test resources, if blank nothing is uploaded
   * @return the updated page with the loaded key store or with the error message
   */
  private HtmlPage uploadKeystore(HtmlPage currentPage,
                                  String name,
                                  String alias,
                                  String keystorePassword,
                                  String keyPassword,
                                  String stringPath)
  {
    setTextValue(currentPage, "keystore-keystoreName", name);
    setTextValue(currentPage, "keystore-alias", alias);
    setPasswordValue(currentPage, "keystore-keystorePassword", keystorePassword);
    setPasswordValue(currentPage, "keystore-privateKeyPassword", keyPassword);

    if (StringUtils.isNotBlank(stringPath))
    {
      HtmlFileInput keystoreFileInput = (HtmlFileInput)currentPage.getElementById("keystore-keystoreFile");
      URL jksKeystoreUrl = getClass().getResource(stringPath);
      File jksKeystore = new File(jksKeystoreUrl.toString());
      keystoreFileInput.setFiles(jksKeystore);
    }

    try
    {
      return click(currentPage, Button.UPLOAD_KEYSTORE);
    }
    catch (IOException e)
    {
      log.error("Cannot upload keystore", e);
      fail("Cannot upload keystore");
      return currentPage;
    }
  }

  /**
   * Click a button
   *
   * @param currentPage
   * @param button
   */
  private HtmlPage click(HtmlPage currentPage, Button button) throws IOException
  {
    HtmlButton htmlButton;

    switch (button)
    {
      case UPLOAD_CERTIFICATE:
        htmlButton = (HtmlButton)currentPage.getElementById("certificate-upload-button");
        break;
      case UPLOAD_KEYSTORE:
        htmlButton = (HtmlButton)currentPage.getElementById("keystore-upload-button");
        break;
      case NEXT_PAGE:
        htmlButton = (HtmlButton)currentPage.getElementById("next-button");
        break;
      case PREVIOUS_PAGE:
        htmlButton = (HtmlButton)currentPage.getElementById("previous-button");
        break;
      default:
        htmlButton = (HtmlButton)currentPage.getElementById("save-button");
        break;
    }

    return htmlButton.click();
  }

  /**
   * Assert that a certain message is displayed in the correct field
   *
   * @param currentPage
   * @param fieldId to specify the correct field
   * @param expected expected message
   */
  private void assertTextPresent(HtmlPage currentPage, String fieldId, String expected)
  {
    DomElement element = currentPage.getElementById(fieldId);
    assertNotNull(element, "field " + fieldId + " should not be null.");
    assertEquals(expected, element.getTextContent(), fieldId + " should be " + expected);
  }

  /**
   * Set a text value
   *
   * @param currentPage
   * @param fieldId to identify the field where the text is set
   * @param text value
   */
  private void setTextValue(HtmlPage currentPage, String fieldId, String text)
  {
    if (currentPage.getElementById(fieldId) instanceof HtmlTextInput)
    {
      HtmlTextInput textInput = (HtmlTextInput)currentPage.getElementById(fieldId);
      textInput.setText(text);
    }
    else if (currentPage.getElementById(fieldId) instanceof HtmlTextArea)
    {
      HtmlTextArea textArea = (HtmlTextArea)currentPage.getElementById(fieldId);
      textArea.setText(text);
    }
    else
    {
      fail("Cannot set text value for field with id " + fieldId + " and class "
           + currentPage.getElementById(fieldId).getClass().getName());
    }
  }

  /**
   * Set a password value
   *
   * @param currentPage
   * @param fieldId to identify the field where the password is set
   * @param text password value
   */
  private void setPasswordValue(HtmlPage currentPage, String fieldId, String text)
  {
    HtmlPasswordInput passwordInput = (HtmlPasswordInput)currentPage.getElementById(fieldId);
    passwordInput.setText(text);
  }

  /**
   * Select a value to set a certificate or key store
   *
   * @param currentPage
   * @param fieldId certificate or key store field id
   * @param value value to be selected
   */
  private void setSelectValue(HtmlPage currentPage, String fieldId, String value)
  {
    HtmlSelect select = (HtmlSelect)currentPage.getElementById(fieldId);
    select.getOptionByValue(value).setSelected(true);
  }

  /**
   * Set a radio button to a selected value by field id
   *
   * @param currentPage
   * @param fieldId field id of the button to be selected
   * @return page with the selected button
   */
  private HtmlPage setRadioButton(HtmlPage currentPage, String fieldId)
  {
    HtmlRadioButtonInput dvcaBudru = (HtmlRadioButtonInput)currentPage.getElementById(fieldId);
    return (HtmlPage)dvcaBudru.setChecked(true);
  }
}
