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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import com.gargoylesoftware.htmlunit.WebAssert;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlRadioButtonInput;
import com.gargoylesoftware.htmlunit.html.HtmlSelect;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;

import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.PoseidasCoreConfigForm;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.PoseidasCoreConfigFormTest;
import de.governikus.eumw.poseidas.config.schema.EPAConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PkiConnectorConfigurationType;
import de.governikus.eumw.poseidas.config.schema.PoseidasCoreConfiguration;
import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;
import de.governikus.eumw.poseidas.config.schema.SslKeysType;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.extern.slf4j.Slf4j;


/**
 * Abstract Base Class for frontend tests
 */
@Slf4j
class ConfigWizardTestBase extends AbstractWebTest
{

  private static final String APPLICATION_PROPERTIES_HSM_KEYS_DELETE = "applicationProperties-hsmKeysDelete";

  private static final String APPLICATION_PROPERTIES_ADDITIONAL_PROPERTIES = "applicationProperties-additionalProperties";

  private static final String APPLICATION_PROPERTIES_LOG_FILE = "applicationProperties-logFile";

  private static final String APPLICATION_PROPERTIES_ADMIN_PASSWORD = "applicationProperties-adminPassword";

  private static final String APPLICATION_PROPERTIES_ADMIN_USERNAME = "applicationProperties-adminUsername";

  private static final String APPLICATION_PROPERTIES_DATASOURCE_PASSWORD = "applicationProperties-datasourcePassword";

  private static final String APPLICATION_PROPERTIES_DATASOURCE_USERNAME = "applicationProperties-datasourceUsername";

  private static final String APPLICATION_PROPERTIES_DATASOURCE_URL = "applicationProperties-datasourceUrl";

  private static final String APPLICATION_PROPERTIES_SERVER_SSL_KEYSTORE = "applicationProperties.serverSslKeystore";

  private static final String APPLICATION_PROPERTIES_ADMIN_INTERFACE_PORT = "applicationProperties-adminInterfacePort";

  private static final String APPLICATION_PROPERTIES_SERVER_PORT_ID = "applicationProperties-serverPort";

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
  static final String KEY_VALIDATE_BLANK = "wizard.status.validation.blank";

  /**
   * message key to the validation message if a field entry is not anumber
   */
  static final String KEY_INVALIDE_NUMBER = "wizard.status.validation.number";

  /**
   * message key to validation message if certificate is not selected
   */
  private static final String KEY_VALIDATE_CERTIFICATE = "wizard.status.validation.certificate";

  /**
   * message key to validation message if keystore is not selected
   */
  static final String KEY_VALIDATE_KEYSTORE = "wizard.status.validation.keystore";

  /**
   * message key to validation message if name for keystore or certificate is missing
   */
  static final String KEY_VALIDATE_UPLOAD_NAME = "wizard.status.validation.upload.name";

  /**
   * message key to validation message if alias for keystore is missing
   */
  static final String KEY_VALIDATE_UPLOAD_ALIAS = "wizard.status.validation.upload.alias";

  /**
   * junit test assertion when the validation of the created application properties failed
   */
  static final String VALIDATE_APPLICATION_PROPERTIES_MESSAGE = "The created application.properties file is not correct.";

  /**
   * junit test assertion when the validation of the created application properties failed
   */
  private static final String VALIDATE_POSEIDAS_XML_MESSAGE = "The created poseidas.xml file is not correct.";

  /**
   * junit test assertion when the validation of the created application properties failed
   */
  static final String VALIDATE_MIDDLEWARE_PROPERTIES_MESSAGE = "The created eidasmiddleware.properties file is not correct.";

  /**
   * name of the folder containing the metadata.xml
   */
  static final String SERVICEPROVIDER_METADATA_FOLDER = "serviceprovider-metadata";

  /**
   * the service provider entity id used in the poseidas.xml and the eidasmiddleware.properties
   */

  static final String SERVICEPROVIDER_ENTITY_ID = "myEntityID";

  /**
   * the server url used in the poseidas.xml and the eidasmiddleware.properties
   */
  static final String SERVER_URL = "https://myhost:8443";

  /**
   * password for accessing the keystores in the resources
   */
  static final String DEFAULT_KEYSTORE_PASSWORD = "123456";

  /**
   * suffix for error field ids
   */
  static final String ERROR_SUFFIX = "-error";

  /**
   * blank text entry
   */
  static final String BLANK = "";

  static final String SERVER_URL_FIELD_ID = "coreConfig-coreConfig.serverUrl";

  static final String BLACK_LIST_FIELD_ID = "poseidasConfig.commonServiceProviderData.blackListTrustAnchor";

  static final String MASTER_LIST_FIELD_ID = "poseidasConfig.commonServiceProviderData.masterListTrustAnchor";

  static final String SERVER_CERTIFICATE_FIELD_ID = "poseidasConfig.commonServiceProviderData.sslKeysForm.serverCertificate";

  static final String DVCA_BUDRU_FIELD_ID = "poseidasConfig.commonServiceProviderData.dvcaProvider1";

  private static final String DVCA_GOVDVCA_FIELD_ID = "poseidasConfig.commonServiceProviderData.dvcaProvider2";

  static final String ENTITY_ID_FIELD_ID = "minimalServiceProviderForm-minimalServiceProviderForm.entityID";

  static final String CLIENT_KEYSTORE_FIELD_ID = "poseidasConfig.minimalServiceProviderForm.sslKeysForm.clientKeyForm";

  private static final String PUBLIC_SERVICE_PROVIDER_FIELD_ID = "minimalServiceProviderForm-minimalServiceProviderForm.publicServiceProvider";

  static final String BLACKLIST_CERT_NAME = "blacklist";

  static final String MASTERLIST_CERT_NAME = "masterlist";

  static final String SERVER_CERT_NAME = "serverCert";

  static final String CLIENT_KEYSTORE_NAME = "clientKeystore";

  /**
   * The root path of the application
   */
  static final String ROOT_PATH = "/";

  /**
   * the folder name where the config should be stored
   */
  static final String CONFIG_TO_BE_WRITTEN = "configToBeWritten";

  /**
   * all possible buttons for identification
   */
  enum Button
  {
    NEXT_PAGE, PREVIOUS_PAGE, SAVE, UPLOAD_CERTIFICATE, UPLOAD_KEYSTORE, UPLOAD_SERVICE_PROVIDER
  }

  /**
   * Upload a certificate
   *
   * @param currentPage The current HTML page
   * @param name the name that should be inserted in the form
   * @param stringPath the path to the file in the test resources, if blank nothing is uploaded
   * @return the updated page with the loaded certificate or with the error message
   */
  HtmlPage uploadCertificate(HtmlPage currentPage, String name, String stringPath)
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
   * @param currentPage The current HTML page
   * @param name the name that should be inserted in the form
   * @param alias the alias of the key in the key store
   * @param keystorePassword the password of the key store
   * @param keyPassword the password of the key
   * @param stringPath the path to the file in the test resources, if blank nothing is uploaded
   * @return the updated page with the loaded key store or with the error message
   */
  HtmlPage uploadKeystore(HtmlPage currentPage,
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
   * @param currentPage The current HTML page
   * @param button The button to be clicked, see {@link Button}
   */
  HtmlPage click(HtmlPage currentPage, Button button) throws IOException
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
      case UPLOAD_SERVICE_PROVIDER:
        htmlButton = (HtmlButton)currentPage.getElementById("service-provider-upload-button");
        break;
      default:
        htmlButton = (HtmlButton)currentPage.getElementById("save-button");
        break;
    }

    return htmlButton.click();
  }

  /**
   * Click a button
   *
   * @param currentPage The current HTML page
   * @param elementId The element ID of the button to be clicked
   */
  HtmlPage click(HtmlPage currentPage, String elementId) throws IOException
  {
    HtmlButton button = (HtmlButton)currentPage.getElementById(elementId);
    return button.click();
  }

  /**
   * Assert that a certain message is displayed in the correct field
   *
   * @param currentPage The current HTML page
   * @param fieldId to specify the correct field
   * @param expected expected message
   */
  void assertValidationMessagePresent(HtmlPage currentPage, String fieldId, String expected)
  {
    DomElement element = currentPage.getElementById(fieldId);
    assertNotNull(element, "field " + fieldId + " should not be null.");
    assertEquals(expected, element.getTextContent(), fieldId + " should be " + expected);
  }

  /**
   * Set a text value
   *
   * @param currentPage The current HTML page
   * @param fieldId to identify the field where the text is set
   * @param text value
   */
  void setTextValue(HtmlPage currentPage, String fieldId, String text)
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
   * @param currentPage The current HTML page
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
   * @param currentPage The current HTML page
   * @param fieldId certificate or key store field id
   * @param value value to be selected
   */
  void setSelectValue(HtmlPage currentPage, String fieldId, String value)
  {
    HtmlSelect select = (HtmlSelect)currentPage.getElementById(fieldId);
    select.getOptionByValue(value).setSelected(true);
  }

  /**
   * Set a radio button to a selected value by field id
   *
   * @param currentPage The current HTML page
   * @param fieldId field id of the button to be selected
   * @return page with the selected button
   */
  HtmlPage setRadioButton(HtmlPage currentPage, String fieldId)
  {
    HtmlRadioButtonInput dvcaBudru = (HtmlRadioButtonInput)currentPage.getElementById(fieldId);
    return (HtmlPage)dvcaBudru.setChecked(true);
  }

  /**
   * Set the checkbox to the given state
   *
   * @param currentPage The current HTML page
   * @param elementID The element ID of the checkbox to be clicked
   * @param selectCheckbox The state for the checkbox
   */
  void setCheckboxValue(HtmlPage currentPage, String elementID, boolean selectCheckbox)
  {
    HtmlCheckBoxInput publicServiceProvider = (HtmlCheckBoxInput)currentPage.getElementById(elementID);
    publicServiceProvider.setChecked(selectCheckbox);
  }

  /**
   * test the page where one can enter the configuration directory
   */
  HtmlPage testConfigDirectoryPage(HtmlPage startPage) throws IOException
  {
    assertNotNull(startPage.getElementById("configDirectory.configDirectory"),
                  "The test should be on page 1 but isn't.");
    return click(startPage, Button.NEXT_PAGE);

  }

  /**
   * test the page where one can upload its old configurations
   */
  HtmlPage testUploadPage(HtmlPage uploadOldConfigurationPage) throws IOException
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
   * test the application property page.
   */
  HtmlPage testApplicationPropertiesPage(HtmlPage currentPage) throws IOException
  {
    // upload necessary ssl keystore
    final String ssl = "ssl";
    HtmlPage currentPageWithKeystore = uploadKeystore(currentPage,
                                                      ssl,
                                                      ssl,
                                                      DEFAULT_KEYSTORE_PASSWORD,
                                                      DEFAULT_KEYSTORE_PASSWORD,
                                                      "/test-files/ssl.jks");
    assertValidationMessagePresent(currentPageWithKeystore,
                                   KEYSTORE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));

    // click next without any entries
    HtmlPage pageBlankError = click(currentPageWithKeystore, Button.NEXT_PAGE);
    assertApplicationValidationMessages(pageBlankError);

    // fill in invalid server port
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_SERVER_PORT_ID, getMessage("server.port"));
    HtmlPage pageNoNumberError = click(currentPageWithKeystore, Button.NEXT_PAGE);
    assertValidationMessagePresent(pageNoNumberError,
                                   APPLICATION_PROPERTIES_SERVER_PORT_ID + ERROR_SUFFIX,
                                   getMessage("wizard.status.validation.number"));

    // fill in form
    fillingApplicationForm(ssl, currentPageWithKeystore);

    return click(currentPageWithKeystore, Button.NEXT_PAGE);
  }

  private void fillingApplicationForm(final String ssl, HtmlPage currentPageWithKeystore)
  {
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_SERVER_PORT_ID, "8080");
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_ADMIN_INTERFACE_PORT, "11111");
    setSelectValue(currentPageWithKeystore, APPLICATION_PROPERTIES_SERVER_SSL_KEYSTORE, ssl);
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_DATASOURCE_URL, "databaseURL");
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_DATASOURCE_USERNAME, "databaseName");
    setPasswordValue(currentPageWithKeystore, APPLICATION_PROPERTIES_DATASOURCE_PASSWORD, "databasePassword");
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_ADMIN_USERNAME, "poseidasUsername");
    setPasswordValue(currentPageWithKeystore, APPLICATION_PROPERTIES_ADMIN_PASSWORD, "poseidasPassword");
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_LOG_FILE, "logFilePath");
    setTextValue(currentPageWithKeystore,
                 APPLICATION_PROPERTIES_ADDITIONAL_PROPERTIES,
                 "logging.level.de.governikus=DEBUG\nlogging.level.foo.bar=ERROR");
  }

  private void assertApplicationValidationMessages(HtmlPage pageBlankError)
  {
    assertValidationMessagePresent(pageBlankError,
                                   APPLICATION_PROPERTIES_SERVER_PORT_ID + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
    assertValidationMessagePresent(pageBlankError,
                                   "serverSslKeystore-error",
                                   getMessage(KEY_VALIDATE_KEYSTORE));
    assertValidationMessagePresent(pageBlankError,
                                   APPLICATION_PROPERTIES_DATASOURCE_URL + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
    assertValidationMessagePresent(pageBlankError,
                                   APPLICATION_PROPERTIES_DATASOURCE_USERNAME + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
    assertValidationMessagePresent(pageBlankError,
                                   APPLICATION_PROPERTIES_DATASOURCE_PASSWORD + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
    assertValidationMessagePresent(pageBlankError,
                                   APPLICATION_PROPERTIES_ADMIN_USERNAME + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
    assertValidationMessagePresent(pageBlankError,
                                   APPLICATION_PROPERTIES_ADMIN_PASSWORD + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
  }

  /**
   * Test the application property page with usage of a hsm.
   */

  HtmlPage testApplicationPropertiesPageWithHSM(HtmlPage currentPage) throws IOException
  {
    final String hsmTypeId = "applicationProperties-hsmType";
    final String hsmTypeValue = "PKCS11";
    final String hsmKeysArchive = "applicationProperties-hsmKeysArchive";
    final String pkcs11ConfigProviderPath = "applicationProperties-pkcs11ConfigProviderPath";
    final String pkcs11HsmPassword = "applicationProperties-pkcs11HsmPassword";


    // upload necessary ssl keystore
    final String ssl = "ssl";
    HtmlPage currentPageWithKeystore = uploadKeystore(currentPage,
                                                      ssl,
                                                      ssl,
                                                      DEFAULT_KEYSTORE_PASSWORD,
                                                      DEFAULT_KEYSTORE_PASSWORD,
                                                      "/test-files/ssl.jks");
    assertValidationMessagePresent(currentPageWithKeystore,
                                   KEYSTORE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));

    setSelectValue(currentPageWithKeystore, hsmTypeId, hsmTypeValue);
    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_HSM_KEYS_DELETE, "bob");
    // click next without any entries
    HtmlPage pageBlankError = click(currentPageWithKeystore, Button.NEXT_PAGE);
    assertApplicationValidationMessages(pageBlankError);

    assertValidationMessagePresent(pageBlankError,
                                   pkcs11ConfigProviderPath + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
    assertValidationMessagePresent(pageBlankError,
                                   pkcs11HsmPassword + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_BLANK));
    assertValidationMessagePresent(pageBlankError,
                                   APPLICATION_PROPERTIES_HSM_KEYS_DELETE + ERROR_SUFFIX,
                                   getMessage(KEY_INVALIDE_NUMBER));

    // fill in form
    fillingApplicationForm(ssl, currentPageWithKeystore);

    setTextValue(currentPageWithKeystore, APPLICATION_PROPERTIES_HSM_KEYS_DELETE, "1");
    setCheckboxValue(currentPageWithKeystore, hsmKeysArchive, true);
    setTextValue(currentPageWithKeystore, pkcs11ConfigProviderPath, "pkcs11ConfigProviderPath");
    setPasswordValue(currentPageWithKeystore, pkcs11HsmPassword, "pkcs11Password");

    return click(currentPageWithKeystore, Button.NEXT_PAGE);
  }


  HtmlPage testPoseidasPageWithHSM(HtmlPage currentPage) throws IOException
  {
    // upload necessary certificates and keystore for poseidas page
    HtmlPage allFilesUploaded = uploadCertificatesAndKeystores(currentPage,
                                                               SERVER_CERT_NAME,
                                                               CLIENT_KEYSTORE_NAME);

    // fill in invalid url, leave other entries empty
    setTextValue(allFilesUploaded, SERVER_URL_FIELD_ID, "no valid url");
    HtmlPage emptyPage = click(allFilesUploaded, Button.NEXT_PAGE);
    assertValidationMessagePresent(emptyPage,
                                   SERVER_URL_FIELD_ID + ERROR_SUFFIX,
                                   getMessage("wizard.status.validation.url"));
    // assertValidationMessagePresent(emptyPage, entityIdFieldId + ERROR_SUFFIX,
    // getMessage("wizard.status.validation.incorrect.default.serviceprovider"));
    WebAssert.assertTextPresent(emptyPage, getMessage("wizard.status.validation.missing.serviceprovider"));
    assertValidationMessagePresent(emptyPage,
                                   "blackListTrustAnchor-error",
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    assertValidationMessagePresent(emptyPage,
                                   "masterListTrustAnchor-error",
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    assertValidationMessagePresent(emptyPage,
                                   "serverCertificate-error",
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    // assertValidationMessagePresent(emptyPage, "clientKeyForm-error", getMessage(KEY_VALIDATE_KEYSTORE));
    assertValidationMessagePresent(emptyPage,
                                   "dvcaProvider-error",
                                   getMessage("wizard.status.validation.dvca.missing"));

    // fill in form
    HtmlPage selectedRadioButtonPage = setRadioButton(allFilesUploaded, DVCA_GOVDVCA_FIELD_ID);
    setTextValue(selectedRadioButtonPage, SERVER_URL_FIELD_ID, SERVER_URL);
    setSelectValue(selectedRadioButtonPage, BLACK_LIST_FIELD_ID, BLACKLIST_CERT_NAME);
    setSelectValue(selectedRadioButtonPage, MASTER_LIST_FIELD_ID, MASTERLIST_CERT_NAME);
    setSelectValue(selectedRadioButtonPage, SERVER_CERTIFICATE_FIELD_ID, SERVER_CERT_NAME);

    setTextValue(selectedRadioButtonPage, ENTITY_ID_FIELD_ID, SERVICEPROVIDER_ENTITY_ID);
    setCheckboxValue(selectedRadioButtonPage, PUBLIC_SERVICE_PROVIDER_FIELD_ID, true);
    HtmlPage uploadedServiceProvider = click(selectedRadioButtonPage, Button.UPLOAD_SERVICE_PROVIDER);

    return click(uploadedServiceProvider, Button.NEXT_PAGE);
  }

  /**
   * test the poseidas page
   */
  HtmlPage testPoseidasPage(HtmlPage currentPage) throws IOException
  {
    // upload necessary certificates and keystore for poseidas page
    HtmlPage allFilesUploaded = uploadCertificatesAndKeystores(currentPage,
                                                               SERVER_CERT_NAME,
                                                               CLIENT_KEYSTORE_NAME);

    // fill in invalid url, leave other entries empty
    setTextValue(allFilesUploaded, SERVER_URL_FIELD_ID, "no valid url");
    HtmlPage emptyPage = click(allFilesUploaded, Button.NEXT_PAGE);
    assertValidationMessagePresent(emptyPage,
                                   SERVER_URL_FIELD_ID + ERROR_SUFFIX,
                                   getMessage("wizard.status.validation.url"));
    // assertValidationMessagePresent(emptyPage, entityIdFieldId + ERROR_SUFFIX,
    // getMessage("wizard.status.validation.incorrect.default.serviceprovider"));
    WebAssert.assertTextPresent(emptyPage, getMessage("wizard.status.validation.missing.serviceprovider"));
    assertValidationMessagePresent(emptyPage,
                                   "blackListTrustAnchor-error",
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    assertValidationMessagePresent(emptyPage,
                                   "masterListTrustAnchor-error",
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    assertValidationMessagePresent(emptyPage,
                                   "serverCertificate-error",
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    // assertValidationMessagePresent(emptyPage, "clientKeyForm-error", getMessage(KEY_VALIDATE_KEYSTORE));
    assertValidationMessagePresent(emptyPage,
                                   "dvcaProvider-error",
                                   getMessage("wizard.status.validation.dvca.missing"));

    // fill in form
    HtmlPage selectedRadioButtonPage = setRadioButton(allFilesUploaded, DVCA_GOVDVCA_FIELD_ID);
    setTextValue(selectedRadioButtonPage, SERVER_URL_FIELD_ID, SERVER_URL);
    setSelectValue(selectedRadioButtonPage, BLACK_LIST_FIELD_ID, BLACKLIST_CERT_NAME);
    setSelectValue(selectedRadioButtonPage, MASTER_LIST_FIELD_ID, MASTERLIST_CERT_NAME);
    setSelectValue(selectedRadioButtonPage, SERVER_CERTIFICATE_FIELD_ID, SERVER_CERT_NAME);

    setTextValue(selectedRadioButtonPage, ENTITY_ID_FIELD_ID, SERVICEPROVIDER_ENTITY_ID);
    setSelectValue(selectedRadioButtonPage, CLIENT_KEYSTORE_FIELD_ID, CLIENT_KEYSTORE_NAME);
    setCheckboxValue(selectedRadioButtonPage, PUBLIC_SERVICE_PROVIDER_FIELD_ID, true);
    HtmlPage uploadedServiceProvider = click(selectedRadioButtonPage, Button.UPLOAD_SERVICE_PROVIDER);

    return click(uploadedServiceProvider, Button.NEXT_PAGE);
  }

  /**
   * Upload the service provider data like trust anchors and server certificate and client keystore
   *
   * @param currentPage The current HTML page
   * @param serverCert The server cert to be uploaded
   * @param clientKeystore The name for the client keystore in the config wizard
   * @return the HTML page with the uploaded data
   */
  HtmlPage uploadCertificatesAndKeystores(HtmlPage currentPage, String serverCert, String clientKeystore)
  {
    HtmlPage blacklistUploaded = uploadCertificate(currentPage, "blacklist", "/test-files/blacklist.pem");
    assertValidationMessagePresent(blacklistUploaded,
                                   CERTIFICATE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage masterlistUploaded = uploadCertificate(blacklistUploaded,
                                                    "masterlist",
                                                    "/test-files/masterlist.pem");
    assertValidationMessagePresent(masterlistUploaded,
                                   CERTIFICATE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage serverCertUploaded = uploadCertificate(masterlistUploaded,
                                                    serverCert,
                                                    "/test-files/dvca_server_cert.pem");
    assertValidationMessagePresent(serverCertUploaded,
                                   CERTIFICATE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage allFilesUploaded = uploadKeystore(serverCertUploaded,
                                               clientKeystore,
                                               "dvca_client",
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               "/test-files/dvca_client.jks");
    assertValidationMessagePresent(allFilesUploaded, KEYSTORE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));
    return allFilesUploaded;
  }


  HtmlPage testEidasMiddlewarePropertiesPageWithHSM(HtmlPage currentPage) throws IOException
  {
    final String metadataFileFieldId = "eidasmiddlewareProperties.uploadedFile";
    final String uploadMetadataButtonId = "metadata-upload-button";
    final String signatureCertificateFieldId = "metadataSignatureCertificate";
    final String cryptKeystoreFieldId = "middlewareCryptKeystore";
    final String countryFieldId = "serviceProvider-countryCode";

    // fill in blank values, leave rest empty
    HtmlPage emptyPage = click(currentPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(emptyPage, getMessage("wizard.status.validation.missing.metadata"));
    assertValidationMessagePresent(emptyPage,
                                   signatureCertificateFieldId + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    assertValidationMessagePresent(emptyPage,
                                   cryptKeystoreFieldId + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_KEYSTORE));
    assertValidationMessagePresent(emptyPage, countryFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));

    // upload necessary certificates and keystore for middleware page
    final String signatureCertificate = "signatureCertificate";
    final String decryptionKeystore = "decryptionKeystore";
    HtmlPage uploadedMetaCert = uploadCertificate(currentPage,
                                                  signatureCertificate,
                                                  "/test-files/serviceProviderMetadataSign.cer");
    assertValidationMessagePresent(uploadedMetaCert,
                                   CERTIFICATE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage allFilesUploaded = uploadKeystore(uploadedMetaCert,
                                               decryptionKeystore,
                                               "middleware_decrypt",
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               "/test-files/middleware_decrypt.p12");
    assertValidationMessagePresent(allFilesUploaded, KEYSTORE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));

    // fill in form
    HtmlFileInput metadataFileInput = (HtmlFileInput)allFilesUploaded.getElementById(metadataFileFieldId);
    File metadataFile = new File(getClass().getResource("/test-files/metadata.xml").toString());
    metadataFileInput.setFiles(metadataFile);
    allFilesUploaded = click(allFilesUploaded, uploadMetadataButtonId);
    fillingEidasMiddlewareForm(signatureCertificate, decryptionKeystore, allFilesUploaded);

    return click(allFilesUploaded, Button.NEXT_PAGE);
  }

  /**
   * test the eidas middleware properties page
   */
  HtmlPage testEidasMiddlewarePropertiesPage(HtmlPage currentPage) throws IOException
  {
    final String metadataFileFieldId = "eidasmiddlewareProperties.uploadedFile";
    final String uploadMetadataButtonId = "metadata-upload-button";
    final String signatureCertificateFieldId = "metadataSignatureCertificate";
    final String signatureKeystoreFieldId = "middlewareSignKeystore";
    final String cryptKeystoreFieldId = "middlewareCryptKeystore";
    final String countryFieldId = "serviceProvider-countryCode";

    // fill in blank values, leave rest empty
    HtmlPage emptyPage = click(currentPage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(emptyPage, getMessage("wizard.status.validation.missing.metadata"));
    assertValidationMessagePresent(emptyPage,
                                   signatureCertificateFieldId + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_CERTIFICATE));
    assertValidationMessagePresent(emptyPage,
                                   signatureKeystoreFieldId + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_KEYSTORE));
    assertValidationMessagePresent(emptyPage,
                                   cryptKeystoreFieldId + ERROR_SUFFIX,
                                   getMessage(KEY_VALIDATE_KEYSTORE));
    assertValidationMessagePresent(emptyPage, countryFieldId + ERROR_SUFFIX, getMessage(KEY_VALIDATE_BLANK));

    // upload necessary certificates and keystore for middleware page
    final String signatureCertificate = "signatureCertificate";
    final String signatureKeystore = "signatureKeystore";
    final String decryptionKeystore = "decryptionKeystore";
    HtmlPage uploadedMetaCert = uploadCertificate(currentPage,
                                                  signatureCertificate,
                                                  "/test-files/serviceProviderMetadataSign.cer");
    assertValidationMessagePresent(uploadedMetaCert,
                                   CERTIFICATE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage uploadedSignKeystore = uploadKeystore(uploadedMetaCert,
                                                   signatureKeystore,
                                                   "middleware_sign",
                                                   DEFAULT_KEYSTORE_PASSWORD,
                                                   DEFAULT_KEYSTORE_PASSWORD,
                                                   "/test-files/middleware_sign.jks");
    assertValidationMessagePresent(uploadedSignKeystore,
                                   KEYSTORE_UPLOAD_SUCCESS,
                                   getMessage(KEY_UPLOAD_SUCCESS));
    HtmlPage allFilesUploaded = uploadKeystore(uploadedSignKeystore,
                                               decryptionKeystore,
                                               "middleware_decrypt",
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               DEFAULT_KEYSTORE_PASSWORD,
                                               "/test-files/middleware_decrypt.p12");
    assertValidationMessagePresent(allFilesUploaded, KEYSTORE_UPLOAD_SUCCESS, getMessage(KEY_UPLOAD_SUCCESS));

    // fill in form
    HtmlFileInput metadataFileInput = (HtmlFileInput)allFilesUploaded.getElementById(metadataFileFieldId);
    File metadataFile = new File(getClass().getResource("/test-files/metadata.xml").toString());
    metadataFileInput.setFiles(metadataFile);
    allFilesUploaded = click(allFilesUploaded, uploadMetadataButtonId);
    setSelectValue(allFilesUploaded, "eidasmiddlewareProperties.middlewareSignKeystore", signatureKeystore);
    fillingEidasMiddlewareForm(signatureCertificate, decryptionKeystore, allFilesUploaded);

    return click(allFilesUploaded, Button.NEXT_PAGE);
  }

  private void fillingEidasMiddlewareForm(final String signatureCertificate,
                                          final String decryptionKeystore,
                                          HtmlPage allFilesUploaded)
  {
    setSelectValue(allFilesUploaded,
                   "eidasmiddlewareProperties.metadataSignatureCertificate",
                   signatureCertificate);
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
  }

  /**
   * check if the entered data in the poseidas.xml is correct
   *
   * @param numberOfServiceProviders The number of expected service providers
   */
  void validateDefaultPoseidasData(int numberOfServiceProviders) throws IOException, CertificateException, // NOPMD
    KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
  {
    final String sslKeysId = "default";

    URL poseidasXmlUrl = Paths.get(getTempDirectory(), "POSeIDAS.xml").toUri().toURL();
    PoseidasCoreConfiguration poseidasConfig = PoseidasCoreConfigFormTest.getPoseidasCoreConfiguration(poseidasXmlUrl);

    validatePoseidasCoreConfiguration(poseidasConfig);

    List<ServiceProviderType> spList = poseidasConfig.getServiceProvider();
    assertEquals(numberOfServiceProviders, spList.size(), VALIDATE_POSEIDAS_XML_MESSAGE); // NOPMD
    ServiceProviderType serviceProvider = spList.get(0);

    validateServiceProvider(sslKeysId,
                            serviceProvider,
                            SERVICEPROVIDER_ENTITY_ID,
                            "/test-files/dvca_client.jks",
                            "dvca_client");
  }

  void validateDefaultPoseidasDataWithHSM(int numberOfServiceProviders)
    throws IOException, CertificateException, // NOPMD
    KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
  {
    final String sslKeysId = "default";

    URL poseidasXmlUrl = Paths.get(getTempDirectory(), "POSeIDAS.xml").toUri().toURL();
    PoseidasCoreConfiguration poseidasConfig = PoseidasCoreConfigFormTest.getPoseidasCoreConfiguration(poseidasXmlUrl);

    validatePoseidasCoreConfiguration(poseidasConfig);

    List<ServiceProviderType> spList = poseidasConfig.getServiceProvider();
    assertEquals(numberOfServiceProviders, spList.size(), VALIDATE_POSEIDAS_XML_MESSAGE); // NOPMD
    ServiceProviderType serviceProvider = spList.get(0);

    validateServiceProvider(sslKeysId, serviceProvider, SERVICEPROVIDER_ENTITY_ID, null, null);
  }

  private void validatePoseidasCoreConfiguration(PoseidasCoreConfiguration poseidasConfig)
  {
    assertEquals("https://myhost:8443/eidas-middleware",
                 poseidasConfig.getServerUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertTrue(poseidasConfig.isSessionManagerUsesDatabase(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(PoseidasCoreConfigForm.SESSION_MAX_PENDING_REQUESTS,
                 poseidasConfig.getSessionMaxPendingRequests(),
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
  }


  /**
   * Validate that the service provider from the POSeIDAS.xml file contains the expected values
   *
   * @param sslKeysId The sslKeysId of this service provider
   * @param serviceProvider The service provider to be validated
   * @param entityId The expected entityID of the service provider
   * @param clientAuthenticationKeystore The expected client keystore of the service provider
   * @param alias The alias for the client keystore
   */
  void validateServiceProvider(String sslKeysId,
                               ServiceProviderType serviceProvider,
                               String entityId,
                               String clientAuthenticationKeystore,
                               String alias)
    throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException,
    UnrecoverableKeyException
  {
    assertEquals(entityId, serviceProvider.getEntityID(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertTrue(serviceProvider.isEnabled(), VALIDATE_POSEIDAS_XML_MESSAGE);

    EPAConnectorConfigurationType epaConnectorConfigurationType = serviceProvider.getEPAConnectorConfiguration();
    assertTrue(epaConnectorConfigurationType.isUpdateCVC(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(entityId, epaConnectorConfigurationType.getCVCRefID(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(SERVER_URL + "/eidas-middleware/paosreceiver",
                 StringUtils.deleteWhitespace(epaConnectorConfigurationType.getPaosReceiverURL()),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    final Integer hoursToRefresh = 240;
    assertEquals(hoursToRefresh, // NOPMD
                 epaConnectorConfigurationType.getHoursRefreshCVCBeforeExpires(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);

    PkiConnectorConfigurationType pkiConnectorConfigurationType = epaConnectorConfigurationType.getPkiConnectorConfiguration();
    assertEqualCertificates(getClass().getResource("/test-files/blacklist.pem"),
                            pkiConnectorConfigurationType.getBlackListTrustAnchor());
    assertEqualCertificates(getClass().getResource("/test-files/masterlist.pem"),
                            pkiConnectorConfigurationType.getMasterListTrustAnchor());
    assertEquals("govDvca",
                 pkiConnectorConfigurationType.getPolicyImplementationId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getTerminalAuthService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://dev.governikus-eid.de:9444/gov_dvca/ta-service",
                 pkiConnectorConfigurationType.getTerminalAuthService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getRestrictedIdService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://dev.governikus-eid.de:9444/gov_dvca/ri-service",
                 pkiConnectorConfigurationType.getRestrictedIdService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getPassiveAuthService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://dev.governikus-eid.de:9444/gov_dvca/pa-service",
                 pkiConnectorConfigurationType.getPassiveAuthService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals(sslKeysId,
                 pkiConnectorConfigurationType.getDvcaCertDescriptionService().getSslKeysId(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEquals("https://dev.governikus-eid.de:9444/gov_dvca/certDesc-service",
                 pkiConnectorConfigurationType.getDvcaCertDescriptionService().getUrl(),
                 VALIDATE_POSEIDAS_XML_MESSAGE);

    List<SslKeysType> sslKeysList = pkiConnectorConfigurationType.getSslKeys();
    assertEquals(1, sslKeysList.size(), VALIDATE_POSEIDAS_XML_MESSAGE); // NOPMD
    assertEquals(sslKeysId, sslKeysList.get(0).getId(), VALIDATE_POSEIDAS_XML_MESSAGE);
    assertEqualCertificates(getClass().getResource("/test-files/dvca_server_cert.pem"),
                            sslKeysList.get(0).getServerCertificate());

    if (StringUtils.isNotBlank(clientAuthenticationKeystore))
    {
      byte[] keystoreBytes = IOUtils.toByteArray(getClass().getResource(clientAuthenticationKeystore));
      KeyStore keystore = KeyStoreSupporter.readKeyStore(keystoreBytes,
                                                         KeyStoreSupporter.KeyStoreType.JKS,
                                                         DEFAULT_KEYSTORE_PASSWORD);

      assertArrayEquals(keystore.getCertificate(alias).getEncoded(),
                        sslKeysList.get(0).getClientCertificate().get(0),
                        VALIDATE_POSEIDAS_XML_MESSAGE);

      assertArrayEquals(keystore.getKey(alias, DEFAULT_KEYSTORE_PASSWORD.toCharArray()).getEncoded(),
                        sslKeysList.get(0).getClientKey(),
                        VALIDATE_POSEIDAS_XML_MESSAGE);
    }

    // assert not needed values are empty
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
   * Create a new directory, put a complete middleware configuration into that directory and adjust the path
   * to the keystores
   *
   * @param pathToConfigDir The path where the config directory should be created
   * @return The path to the created config directory
   */
  Path prepareConfigDir(URL pathToConfigDir) throws IOException, URISyntaxException
  {
    String tmpDir = getTempDirectory();
    Path configToBeRead = Files.createDirectory(Paths.get(tmpDir, "configToBeRead"));

    FileUtils.copyDirectory(Paths.get(pathToConfigDir.toURI()).toFile(), configToBeRead.toFile());

    setPathInConfig(configToBeRead.resolve("application.properties"), configToBeRead);
    setPathInConfig(configToBeRead.resolve("eidasmiddleware.properties"), configToBeRead);

    return configToBeRead;
  }

  /**
   * Read the config file, replace the placeholder $CONFIGPATH with the real path to this config directory and
   * save the config file
   *
   * @param pathToConfigFile The path to the file that should be adjusted
   * @param pathToConfigDir The path to the config directory
   */
  private void setPathInConfig(Path pathToConfigFile, Path pathToConfigDir) throws IOException
  {
    String content = new String(Files.readAllBytes(pathToConfigFile), StandardCharsets.UTF_8);
    String escapedPath = pathToConfigDir.toString().replace("\\", "/");
    content = content.replace("$CONFIGPATH", escapedPath);
    Files.write(pathToConfigFile, content.getBytes(StandardCharsets.UTF_8));
  }
}
