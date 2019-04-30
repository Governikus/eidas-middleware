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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlDetails;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;

import de.governikus.eumw.configuration.wizard.web.handler.HandlerHolder;
import de.governikus.eumw.configuration.wizard.web.model.CertificateForm;
import de.governikus.eumw.configuration.wizard.web.model.KeystoreForm;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.KeyStoreSupporter.KeyStoreType;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 12.02.2018 - 08:55 <br>
 * <br>
 * tests to validate the behaviour of the configuration view
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("test view components of the configuration wizard")
public class ConfigurationWizardControllerTest extends AbstractWebTest // NOPMD
{

  /**
   * Used as string suffix for errors
   */
  private static final String ERROR_SUFFIX = "-error";

  /**
   * to indicate if a details-html-element is currently open or closed
   */
  private static final String OPEN = "open";

  /**
   * clear the state that was created after the current test-method
   */
  @AfterEach
  public void destroy()
  {
    HandlerHolder.getKeystoreHandler().clear();
    HandlerHolder.getCertificateHandler().clear();
  }

  /**
   * this test will check if the upload of a given certificate will be successful
   */
  @TestFactory
  @DisplayName("upload a certificate")
  public List<DynamicTest> uploadCertificate() throws IOException // NOPMD
  {
    final String certificateUploadViewId = "certificate-upload-view";

    final String idBase = "certificate-";
    final String certificateNameId = idBase + "certificateName";
    final String certificateFileId = idBase + "certificateFile";
    final String certificateUploadId = "certificate-upload-button";
    final String certificateUploadSuccessId = "certificateUploadSuccess";
    // @CHECKSTYLE:OFF
    List<DynamicTest> dynamicTests = new ArrayList<>();
    // @CHECKSTYLE:ON

    final HtmlPage originalPage = getWebClient().getPage(getRequestUrl("/"));
    final HtmlTextInput certificateNameInput = (HtmlTextInput)originalPage.getElementById(certificateNameId);
    final HtmlFileInput certificateFileInput = (HtmlFileInput)originalPage.getElementById(certificateFileId);
    final HtmlButton certificateUpload = (HtmlButton)originalPage.getElementById(certificateUploadId);
    Assertions.assertNotNull(certificateNameInput);
    Assertions.assertNotNull(certificateFileInput);
    Assertions.assertNotNull(certificateUpload);

    final String certificateName = "blacklist-trust-anchor";
    final X509Certificate certificate = KeyReader.readX509Certificate(IOUtils.toByteArray(getClass().getResource("/test-files/test.cer")));

    certificateNameInput.setText(certificateName);
    File certificateFile = new File(getClass().getResource("/test-files/test.cer").toString());
    certificateFileInput.setFiles(certificateFile);

    HtmlDetails cd = (HtmlDetails)originalPage.getElementById(certificateUploadViewId);
    Assertions.assertEquals("", cd.getAttribute(OPEN));

    final HtmlPage[] resultPage = new HtmlPage[1];

    dynamicTests.add(DynamicTest.dynamicTest("add certificate -> success", () -> {
      resultPage[0] = certificateUpload.click();
      // now a new element should have been added to the certificate handler
      Assertions.assertEquals(1, HandlerHolder.getCertificateHandler().getAll().size());
      Assertions.assertNotNull(HandlerHolder.getCertificateHandler().getByName(certificateName));
      Assertions.assertNotNull(HandlerHolder.getCertificateHandler()
                                            .getByName(certificateName)
                                            .getCertificate());
      Assertions.assertEquals(certificate,
                              HandlerHolder.getCertificateHandler()
                                           .getByName(certificateName)
                                           .getCertificate());
      CertificateForm certificateForm = HandlerHolder.getCertificateHandler().getByName(certificateName);
      Assertions.assertNotNull(certificateForm);
      Assertions.assertEquals(certificateName, certificateForm.getName());
      // get the input fields from the result page
      HtmlTextInput cni = (HtmlTextInput)resultPage[0].getElementById(certificateNameId);
      Assertions.assertEquals("", cni.getText());
      // assert that no errors are displayed on the view
      Assertions.assertNull(resultPage[0].getElementById(certificateNameId + ERROR_SUFFIX));
      Assertions.assertNull(resultPage[0].getElementById(certificateFileId + ERROR_SUFFIX));
      Assertions.assertNotNull(resultPage[0].getElementById(certificateUploadSuccessId));

      HtmlDetails certificateDetails = (HtmlDetails)resultPage[0].getElementById(certificateUploadViewId);
      Assertions.assertEquals(OPEN, certificateDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add certificate no file added -> fail", () -> {
      HtmlTextInput cni = (HtmlTextInput)resultPage[0].getElementById(certificateNameId);
      HtmlButton cub = (HtmlButton)resultPage[0].getElementById(certificateUploadId);

      // refill the form with new data (we do not send a file this time)
      cni.setText(certificateName + "2");
      resultPage[0] = cub.click();

      cni = (HtmlTextInput)resultPage[0].getElementById(certificateNameId);

      // assert that only the certificate file error message is displayed in the view
      Assertions.assertNull(resultPage[0].getElementById(certificateNameId + ERROR_SUFFIX));
      DomElement certificateFileError = resultPage[0].getElementById(certificateFileId + ERROR_SUFFIX);
      Assertions.assertNotNull(certificateFileError);
      Assertions.assertEquals(getMessage("wizard.status.validation.upload.file")
                              + "could not read certificate for empty certificate bytes",
                              certificateFileError.getTextContent());

      // assert that the certificate name is still present in the text field
      Assertions.assertEquals(certificateName + "2", cni.getText());

      HtmlDetails certificateDetails = (HtmlDetails)resultPage[0].getElementById(certificateUploadViewId);
      Assertions.assertEquals(OPEN, certificateDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add certificate ambigious name -> fail", () -> {
      HtmlTextInput cni = (HtmlTextInput)resultPage[0].getElementById(certificateNameId);
      HtmlFileInput cfi = (HtmlFileInput)resultPage[0].getElementById(certificateFileId);
      HtmlButton cub = (HtmlButton)resultPage[0].getElementById(certificateUploadId);

      // now reuse the once succeded certificate name and get an error message that the name was already used.
      cni.setText(certificateName);
      cfi.setFiles(certificateFile);

      resultPage[0] = cub.click();

      Assertions.assertEquals(1, HandlerHolder.getCertificateHandler().getAll().size());
      Assertions.assertNotNull(HandlerHolder.getCertificateHandler().getByName(certificateName));
      Assertions.assertNotNull(HandlerHolder.getCertificateHandler()
                                            .getByName(certificateName)
                                            .getCertificate());
      Assertions.assertEquals(certificate,
                              HandlerHolder.getCertificateHandler()
                                           .getByName(certificateName)
                                           .getCertificate());
      CertificateForm certificateForm = HandlerHolder.getCertificateHandler().getByName(certificateName);
      Assertions.assertNotNull(certificateForm);
      Assertions.assertEquals(certificateName, certificateForm.getName());
      // get the input fields from the result page
      cni = (HtmlTextInput)resultPage[0].getElementById(certificateNameId);
      Assertions.assertEquals("", cni.getText());
      // assert that no errors are displayed on the view
      Assertions.assertNull(resultPage[0].getElementById(certificateNameId + ERROR_SUFFIX));
      Assertions.assertNull(resultPage[0].getElementById(certificateFileId + ERROR_SUFFIX));
      Assertions.assertNotNull(resultPage[0].getElementById(certificateUploadSuccessId));

      // TODO change back if we decide to revert replacement behaviour
      // DomElement certificateNameError = resultPage[0].getElementById(certificateNameId + ERROR_SUFFIX);
      // Assertions.assertNotNull(certificateNameError);
      // Assertions.assertEquals(new InvalidNameException(certificateName).getMessage(),
      // certificateNameError.getTextContent());
      // Assertions.assertNull(resultPage[0].getElementById(certificateFileId + ERROR_SUFFIX));
      //
      // HtmlDetails certificateDetails = (HtmlDetails)resultPage[0].getElementById(certificateUploadViewId);
      // Assertions.assertEquals(OPEN, certificateDetails.getAttribute(OPEN));
    }));
    return dynamicTests;
  }

  /**
   * this test will check if the upload of a given keystore will be successful
   */
  @TestFactory
  @DisplayName("upload a keystore")
  public List<DynamicTest> uploadKeystore() throws IOException // NOPMD
  {
    // @CHECKSTYLE:OFF
    List<DynamicTest> dynamicTests = new ArrayList<>();
    // @CHECKSTYLE:ON

    final String keystoreUploadViewId = "keystore-upload-view";

    final String idBase = "keystore-";
    final String keystoreNameId = idBase + "keystoreName";
    final String keystoreAliasId = idBase + "alias";
    final String keystorePasswordId = idBase + "keystorePassword";
    final String privateKeyPasswordId = idBase + "privateKeyPassword";
    final String keystoreFileId = idBase + "keystoreFile";
    final String keystoreUploadId = "keystore-upload-button";
    final String keystoreUploadSuccessId = "keystoreUploadSuccess";

    final HtmlPage originalPage = getWebClient().getPage(getRequestUrl("/"));
    final HtmlTextInput keystoreNameInput = (HtmlTextInput)originalPage.getElementById(keystoreNameId);
    final HtmlTextInput keystoreAliasInput = (HtmlTextInput)originalPage.getElementById(keystoreAliasId);
    final HtmlPasswordInput keystorePasswordInput = (HtmlPasswordInput)originalPage.getElementById(keystorePasswordId);
    final HtmlPasswordInput privateKeyPasswordInput = (HtmlPasswordInput)originalPage.getElementById(privateKeyPasswordId);
    final HtmlFileInput keystoreFileInput = (HtmlFileInput)originalPage.getElementById(keystoreFileId);
    final HtmlButton keystoreUpload = (HtmlButton)originalPage.getElementById(keystoreUploadId);
    Assertions.assertNotNull(keystoreNameInput);
    Assertions.assertNotNull(keystoreAliasInput);
    Assertions.assertNotNull(keystorePasswordInput);
    Assertions.assertNotNull(privateKeyPasswordInput);
    Assertions.assertNotNull(keystoreFileInput);
    Assertions.assertNotNull(keystoreUpload);

    final String alias = "test";
    final String keystorePassword = "123456";
    final String privateKeyPassword = keystorePassword;

    final URL jksKeystoreUrl = getClass().getResource("/test-files/junit-test.jks");
    final File jksKeystoreFile = new File(jksKeystoreUrl.toString());

    final URL pkcs12KeystoreUrl = getClass().getResource("/test-files/junit-test.p12");
    final File pkcs12KeystoreFile = new File(pkcs12KeystoreUrl.toString());

    final KeyStore jksKeyStore = KeyStoreSupporter.readKeyStore(IOUtils.toByteArray(jksKeystoreUrl), KeyStoreType.JKS, keystorePassword);
    final KeyStore pkcs12KeyStore = KeyStoreSupporter.readKeyStore(IOUtils.toByteArray(pkcs12KeystoreUrl), KeyStoreType.PKCS12, keystorePassword);

    HtmlDetails kd = (HtmlDetails)originalPage.getElementById(keystoreUploadViewId);
    Assertions.assertEquals("", kd.getAttribute(OPEN));

    dynamicTests.add(DynamicTest.dynamicTest("add keystore JKS -> success", () -> {
      final String keystoreName = "ssl-keystore-jks-success";
      keystoreNameInput.setText(keystoreName);
      keystoreAliasInput.setText(alias);
      keystorePasswordInput.setText(keystorePassword);
      privateKeyPasswordInput.setText(privateKeyPassword);
      keystoreFileInput.setFiles(jksKeystoreFile);
      HtmlPage resultPage = keystoreUpload.click();

      final DomElement nameError = resultPage.getElementById(keystoreNameId + ERROR_SUFFIX);
      final DomElement aliasError = resultPage.getElementById(keystoreAliasId + ERROR_SUFFIX);
      final DomElement passwordError = resultPage.getElementById(keystorePasswordId + ERROR_SUFFIX);
      final DomElement keyError = resultPage.getElementById(privateKeyPasswordId + ERROR_SUFFIX);
      final DomElement fileError = resultPage.getElementById(keystoreFileId + ERROR_SUFFIX);
      final DomElement uploadSuccess = resultPage.getElementById(keystoreUploadSuccessId);
      Assertions.assertNull(nameError);
      Assertions.assertNull(aliasError);
      Assertions.assertNull(passwordError);
      Assertions.assertNull(keyError);
      Assertions.assertNull(fileError);
      Assertions.assertNotNull(uploadSuccess);

      KeystoreForm keystoreForm = HandlerHolder.getKeystoreHandler().getByName(keystoreName);
      Assertions.assertNotNull(keystoreForm);
      Assertions.assertEquals(1, HandlerHolder.getKeystoreHandler().getAll().size());

      Assertions.assertNotNull(keystoreForm.getKeystore());
      Assertions.assertNotNull(keystoreForm.getKeystore().getCertificate(alias));
      Assertions.assertEquals(jksKeyStore.getCertificate(alias), keystoreForm.getKeystore().getCertificate(alias));
      Assertions.assertNotNull(keystoreForm.getKeystore().getKey(alias, privateKeyPassword.toCharArray()));

      HtmlDetails keystoreDetails = (HtmlDetails)resultPage.getElementById(keystoreUploadViewId);
      Assertions.assertEquals(OPEN, keystoreDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add keystore PKCS12 -> success", () -> {
      final String keystoreName = "ssl-keystore-pkcs12-success";
      keystoreNameInput.setText(keystoreName);
      keystoreAliasInput.setText(alias);
      keystorePasswordInput.setText(keystorePassword);
      privateKeyPasswordInput.setText(privateKeyPassword);
      keystoreFileInput.setFiles(pkcs12KeystoreFile);
      HtmlPage resultPage = keystoreUpload.click();

      final DomElement nameError = resultPage.getElementById(keystoreNameId + ERROR_SUFFIX);
      final DomElement aliasError = resultPage.getElementById(keystoreAliasId + ERROR_SUFFIX);
      final DomElement passwordError = resultPage.getElementById(keystorePasswordId + ERROR_SUFFIX);
      final DomElement keyError = resultPage.getElementById(privateKeyPasswordId + ERROR_SUFFIX);
      final DomElement fileError = resultPage.getElementById(keystoreFileId + ERROR_SUFFIX);
      final DomElement uploadSuccess = resultPage.getElementById(keystoreUploadSuccessId);
      Assertions.assertNull(nameError);
      Assertions.assertNull(aliasError);
      Assertions.assertNull(passwordError);
      Assertions.assertNull(keyError);
      Assertions.assertNull(fileError);
      Assertions.assertNotNull(uploadSuccess);

      KeystoreForm keystoreForm = HandlerHolder.getKeystoreHandler().getByName(keystoreName);
      Assertions.assertNotNull(keystoreForm);
      Assertions.assertEquals(2, HandlerHolder.getKeystoreHandler().getAll().size());

      Assertions.assertNotNull(keystoreForm.getKeystore());
      Assertions.assertNotNull(keystoreForm.getKeystore().getCertificate(alias));
      Assertions.assertEquals(pkcs12KeyStore.getCertificate(alias), keystoreForm.getKeystore().getCertificate(alias));
      Assertions.assertNotNull(keystoreForm.getKeystore().getKey(alias, privateKeyPassword.toCharArray()));

      HtmlDetails keystoreDetails = (HtmlDetails)resultPage.getElementById(keystoreUploadViewId);
      Assertions.assertEquals(OPEN, keystoreDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add keystore no file added -> fail", () -> {
      final String keystoreName = "ssl-keystore-no-file-added";
      keystoreNameInput.setText(keystoreName);
      keystoreAliasInput.setText(alias);
      keystorePasswordInput.setText(keystorePassword);
      privateKeyPasswordInput.setText(privateKeyPassword);
      keystoreFileInput.reset();
      HtmlPage resultPage = keystoreUpload.click();

      final DomElement nameError = resultPage.getElementById(keystoreNameId + ERROR_SUFFIX);
      final DomElement aliasError = resultPage.getElementById(keystoreAliasId + ERROR_SUFFIX);
      final DomElement passwordError = resultPage.getElementById(keystorePasswordId + ERROR_SUFFIX);
      final DomElement keyError = resultPage.getElementById(privateKeyPasswordId + ERROR_SUFFIX);
      final DomElement fileError = resultPage.getElementById(keystoreFileId + ERROR_SUFFIX);
      final DomElement uploadSuccess = resultPage.getElementById(keystoreUploadSuccessId);
      Assertions.assertNull(nameError);
      Assertions.assertNull(aliasError);
      Assertions.assertNull(passwordError);
      Assertions.assertNull(keyError);
      Assertions.assertNotNull(fileError);
      Assertions.assertNull(uploadSuccess);

      KeystoreForm keystoreForm = HandlerHolder.getKeystoreHandler().getByName(keystoreName);
      Assertions.assertNull(keystoreForm);
      Assertions.assertEquals(2, HandlerHolder.getKeystoreHandler().getAll().size());

      HtmlDetails keystoreDetails = (HtmlDetails)resultPage.getElementById(keystoreUploadViewId);
      Assertions.assertEquals(OPEN, keystoreDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add keystore ambigious name -> fail", () -> {
      // this name was already used in one of the previous dynamic tests!
      final String keystoreName = "ssl-keystore-jks-success";
      keystoreNameInput.setText(keystoreName);
      keystoreAliasInput.setText(alias);
      keystorePasswordInput.setText(keystorePassword);
      privateKeyPasswordInput.setText(privateKeyPassword);
      keystoreFileInput.setFiles(jksKeystoreFile);
      HtmlPage resultPage = keystoreUpload.click();

      final DomElement nameError = resultPage.getElementById(keystoreNameId + ERROR_SUFFIX);
      final DomElement aliasError = resultPage.getElementById(keystoreAliasId + ERROR_SUFFIX);
      final DomElement passwordError = resultPage.getElementById(keystorePasswordId + ERROR_SUFFIX);
      final DomElement keyError = resultPage.getElementById(privateKeyPasswordId + ERROR_SUFFIX);
      final DomElement fileError = resultPage.getElementById(keystoreFileId + ERROR_SUFFIX);
      final DomElement uploadSuccess = resultPage.getElementById(keystoreUploadSuccessId);
      Assertions.assertNull(nameError);
      // TODO maybe revert
      // Assertions.assertNotNull(nameError);
      // Assertions.assertEquals(new InvalidNameException(keystoreName).getMessage(),
      // nameError.getTextContent());
      Assertions.assertNull(aliasError);
      Assertions.assertNull(passwordError);
      Assertions.assertNull(keyError);
      Assertions.assertNull(fileError);
      // Assertions.assertNull(uploadSuccess);
      Assertions.assertNotNull(uploadSuccess);

      KeystoreForm keystoreForm = HandlerHolder.getKeystoreHandler().getByName(keystoreName);
      Assertions.assertNotNull(keystoreForm);
      Assertions.assertEquals(2, HandlerHolder.getKeystoreHandler().getAll().size());

      HtmlDetails keystoreDetails = (HtmlDetails)resultPage.getElementById(keystoreUploadViewId);
      Assertions.assertEquals(OPEN, keystoreDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add keystore missing alias -> fail", () -> {
      final String keystoreName = "ssl-keystore-missing-alias";
      keystoreNameInput.setText(keystoreName);
      keystoreAliasInput.setText("");
      keystorePasswordInput.setText(keystorePassword);
      privateKeyPasswordInput.setText(privateKeyPassword);
      keystoreFileInput.setFiles(jksKeystoreFile);
      HtmlPage resultPage = keystoreUpload.click();

      final DomElement nameError = resultPage.getElementById(keystoreNameId + ERROR_SUFFIX);
      final DomElement aliasError = resultPage.getElementById(keystoreAliasId + ERROR_SUFFIX);
      final DomElement passwordError = resultPage.getElementById(keystorePasswordId + ERROR_SUFFIX);
      final DomElement keyError = resultPage.getElementById(privateKeyPasswordId + ERROR_SUFFIX);
      final DomElement fileError = resultPage.getElementById(keystoreFileId + ERROR_SUFFIX);
      final DomElement uploadSuccess = resultPage.getElementById(keystoreUploadSuccessId);
      Assertions.assertNull(nameError);
      Assertions.assertNotNull(aliasError);
      Assertions.assertEquals(getMessage("wizard.status.validation.upload.alias"),
                              aliasError.getTextContent());
      Assertions.assertNull(passwordError);
      Assertions.assertNull(keyError);
      Assertions.assertNull(fileError);
      Assertions.assertNull(uploadSuccess);

      Assertions.assertEquals(2, HandlerHolder.getKeystoreHandler().getAll().size());

      HtmlDetails keystoreDetails = (HtmlDetails)resultPage.getElementById(keystoreUploadViewId);
      Assertions.assertEquals(OPEN, keystoreDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add keystore wrong keystore password -> fail", () -> {
      final String keystoreName = "ssl-keystore-wrong-keystore-password";
      keystoreNameInput.setText(keystoreName);
      keystoreAliasInput.setText(alias);
      keystorePasswordInput.setText(keystorePassword + "1");
      privateKeyPasswordInput.setText(privateKeyPassword);
      keystoreFileInput.setFiles(jksKeystoreFile);
      HtmlPage resultPage = keystoreUpload.click();

      final DomElement nameError = resultPage.getElementById(keystoreNameId + ERROR_SUFFIX);
      final DomElement aliasError = resultPage.getElementById(keystoreAliasId + ERROR_SUFFIX);
      final DomElement passwordError = resultPage.getElementById(keystorePasswordId + ERROR_SUFFIX);
      final DomElement keyError = resultPage.getElementById(privateKeyPasswordId + ERROR_SUFFIX);
      final DomElement fileError = resultPage.getElementById(keystoreFileId + ERROR_SUFFIX);
      final DomElement uploadSuccess = resultPage.getElementById(keystoreUploadSuccessId);
      Assertions.assertNull(nameError);
      Assertions.assertNull(aliasError);
      Assertions.assertNotNull(passwordError);
      Assertions.assertNull(keyError);
      Assertions.assertNull(fileError);
      Assertions.assertNull(uploadSuccess);

      Assertions.assertEquals(2, HandlerHolder.getKeystoreHandler().getAll().size());

      HtmlDetails keystoreDetails = (HtmlDetails)resultPage.getElementById(keystoreUploadViewId);
      Assertions.assertEquals(OPEN, keystoreDetails.getAttribute(OPEN));
    }));

    dynamicTests.add(DynamicTest.dynamicTest("add keystore wrong private key password -> fail", () -> {
      /*
       * TODO pkcs12 keystore reading fails if any entry has another password than the keystore itself. Error
       * in BouncyCastle?
       */
      // final String keystoreName = "ssl-keystore-wrong-private-key-password";
      // keystoreNameInput.setText(keystoreName);
      // keystoreAliasInput.setText(alias);
      // keystorePasswordInput.setText(keystorePassword);
      // privateKeyPasswordInput.setText(privateKeyPassword + "1");
      // keystoreFileInput.setFiles(jksKeystore);
      // HtmlPage resultPage = keystoreUpload.click();
      //
      // final DomElement nameError = resultPage.getElementById(keystoreNameId + "-error");
      // final DomElement aliasError = resultPage.getElementById(keystoreAliasId + "-error");
      // final DomElement passwordError = resultPage.getElementById(keystorePasswordId + "-error");
      // final DomElement keyError = resultPage.getElementById(privateKeyPasswordId + "-error");
      // final DomElement fileError = resultPage.getElementById(keystoreFileId + "-error");
      // final DomElement uploadSuccess = resultPage.getElementById(keystoreUploadSuccessId);
      // Assertions.assertNull(nameError);
      // Assertions.assertNull(aliasError);
      // Assertions.assertNull(passwordError);
      // Assertions.assertNotNull(keyError);
      // Assertions.assertNull(fileError);
      // Assertions.assertNull(uploadSuccess);
      //
      // Assertions.assertEquals(2, HandlerHolder.getKeystoreHandler().getAll().size());
    }));

    return dynamicTests;
  }

  /**
   * will test that the the application properties can be set correctly and that the validation is working
   * correctly
   */
  @TestFactory // NOPMD
  @DisplayName("test application properties settings")
  public List<DynamicTest> testApplicationPropertiesSettings() throws IOException // NOPMD
  {
    // @CHECKSTYLE:OFF
    List<DynamicTest> dynamicTests = new ArrayList<>();
    // @CHECKSTYLE:ON

    final String idBase = "applicationProperties-";
    final String appPropertiesServerPortId = idBase + "serverPort";
    final String appPropertiesDatasourceUrlId = idBase + "datasourceUrl";
    final String appPropertiesDatasourceUsernameId = idBase + "datasourceUsername";
    final String appPropertiesDatasourcePasswordId = idBase + "datasourcePassword";
    final String appPropertiesAdminUserId = idBase + "adminUsername";
    final String appPropertiesAdminPasswordId = idBase + "adminPassword";
    final String appPropertiesLogfileId = idBase + "logFile";
    final String nextButtonId = "next-button";
    final String configDirectorId = "configDirectory.configDirectory";
    final String poseidasFileUploadId = "poseidasConfig.poseidasConfigXmlFile";
    final String applicationPropertiesUploadId = "applicationProperties.applicationPropertiesFile";
    final String eidasMiddlewareUploadId = "eidasmiddlewareProperties.eidasPropertiesFile";
    final String basePathInputId = "configDirectory.configDirectory";



    HtmlPage tmpPage = getWebClient().getPage(getRequestUrl("/"));
    HtmlButton tmpNextPage = (HtmlButton)tmpPage.getElementById(nextButtonId);
    HtmlTextInput basePathInput = (HtmlTextInput)tmpPage.getElementById(basePathInputId);
    Assertions.assertNotNull(basePathInput, "base path input text field must exist");
    final String elementWithId = "Element with ID '";
    final String mustBePresent = "' must be present";
    Assertions.assertNotNull(tmpPage.getElementById(configDirectorId),
                             elementWithId + configDirectorId + mustBePresent);
    tmpPage = tmpNextPage.click();
    Assertions.assertNotNull(tmpPage.getElementById(poseidasFileUploadId),
                             elementWithId + poseidasFileUploadId + mustBePresent + "\nHTML:\n "
                                                                           + tmpPage.asXml());
    Assertions.assertNotNull(tmpPage.getElementById(applicationPropertiesUploadId),
                             elementWithId + applicationPropertiesUploadId + mustBePresent + "\nHTML:\n "
                                                                                    + tmpPage.asXml());
    Assertions.assertNotNull(tmpPage.getElementById(eidasMiddlewareUploadId),
                             elementWithId + eidasMiddlewareUploadId + mustBePresent + "\nHTML:\n "
                                                                              + tmpPage.asXml());
    final HtmlPage originalPage = tmpNextPage.click();

    final HtmlTextInput serverPortInput = (HtmlTextInput)originalPage.getElementById(appPropertiesServerPortId);
    final HtmlTextInput datasourceUrlInput = (HtmlTextInput)originalPage.getElementById(appPropertiesDatasourceUrlId);
    final HtmlTextInput datasourceUserInput = (HtmlTextInput)originalPage.getElementById(appPropertiesDatasourceUsernameId);
    final HtmlPasswordInput datasourcePasswordInput = (HtmlPasswordInput)originalPage.getElementById(appPropertiesDatasourcePasswordId);
    final HtmlTextInput adminUserInput = (HtmlTextInput)originalPage.getElementById(appPropertiesAdminUserId);
    final HtmlPasswordInput adminUserPasswordInput = (HtmlPasswordInput)originalPage.getElementById(appPropertiesAdminPasswordId);
    final HtmlTextInput logfileInput = (HtmlTextInput)originalPage.getElementById(appPropertiesLogfileId);
    final HtmlButton nextPage = (HtmlButton)originalPage.getElementById(nextButtonId);

    dynamicTests.add(DynamicTest.dynamicTest("set no properties -> fail", () -> {
      HtmlPage resultPage = nextPage.click();

      Assertions.assertNotNull(resultPage.getElementById(appPropertiesServerPortId + ERROR_SUFFIX),
                               elementWithId + appPropertiesServerPortId + ERROR_SUFFIX + mustBePresent);
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesDatasourceUrlId + ERROR_SUFFIX),
                               elementWithId + appPropertiesDatasourceUrlId + ERROR_SUFFIX + mustBePresent);
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesDatasourceUsernameId + ERROR_SUFFIX),
                               elementWithId + appPropertiesDatasourceUsernameId + ERROR_SUFFIX + mustBePresent);
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesDatasourcePasswordId + ERROR_SUFFIX),
                               elementWithId + appPropertiesDatasourcePasswordId + ERROR_SUFFIX + mustBePresent);
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesAdminUserId + ERROR_SUFFIX),
                               elementWithId + appPropertiesAdminUserId + ERROR_SUFFIX + mustBePresent);
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesAdminPasswordId + ERROR_SUFFIX),
                               elementWithId + appPropertiesAdminPasswordId + ERROR_SUFFIX + mustBePresent);
    }));

    dynamicTests.add(DynamicTest.dynamicTest("set wrong properties -> fail", () -> {
      final String blank = " ";

      serverPortInput.setText("no port");
      datasourceUrlInput.setText(blank);
      datasourceUserInput.setText(blank);
      datasourcePasswordInput.setText(blank);
      adminUserInput.setText(blank);
      adminUserPasswordInput.setText(blank);
      logfileInput.setText(blank);

      HtmlPage resultPage = nextPage.click();

      Assertions.assertNotNull(resultPage.getElementById(appPropertiesServerPortId + ERROR_SUFFIX));
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesDatasourceUrlId + ERROR_SUFFIX));
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesDatasourceUsernameId + ERROR_SUFFIX));
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesDatasourcePasswordId + ERROR_SUFFIX));
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesAdminUserId + ERROR_SUFFIX));
      Assertions.assertNotNull(resultPage.getElementById(appPropertiesAdminPasswordId + ERROR_SUFFIX));
    }));

    return dynamicTests;
  }
}
