/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;


/**
 * Test the admin ui for the key management
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test key management page")
class KeymanagementControllerTest extends WebAdminTestBase
{

  public static final String CERTIFICATE_UPLOAD_NAME_ID = "certificateName";

  public static final String CERTIFICATE_UPLOAD_FILE_INPUT_ID = "certificate-upload";

  public static final String KEY_STORE_UPLOAD_FORM_ID = "KeyStoreUpload";

  public static final String KEYSTORE_UPLOAD_NAME_ID = "keyStoreName";

  public static final String KEYSTORE_UPLOAD_PASSWORD_ID = "Key-store-password";

  public static final String KEYSTORE_UPLOAD_KEYSTORE_TYPE_ID = "keyStoreType";

  public static final String KEYSTORE_UPLOAD_FILE_ID = "keystore-upload";

  public static final String EXTRACT_CERTIFICATE_NAME_ID = "certificateName";

  public static final String EXTRACT_CERTIFICATE_ALIAS_ID = "certalias";

  public static final String EXTRACT_CERTIFICATE_FORM_ID = "extractCertificateForm";

  public static final String EXTRACT_KEY_PAIR_FORM_ID = "extractKeyPairForm";

  public static final String EXTRACT_KEY_PAIR_NAME_ID = "keyPairName";

  public static final String EXTRACT_KEY_PAIR_ALIAS_ID = "keyPairalias";

  public static final String EXTRACT_KEY_PAIR_PASSWORD_ID = "Key-pair-password";

  public static final String TEST_KEY_STORE_PASSWORD = "123456";

  public static final String TEST_KEY_STORE_TYPE = "JKS";

  private static final String KEY_MANAGEMENT_PATH = ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.KEY_MANAGEMENT;

  public static final Predicate<HtmlAnchor> EXTRACT_FROM_KEYSTORE_ANCHOR_PREDICATE = htmlAnchor -> htmlAnchor.getHrefAttribute()
                                                                                                             .startsWith(KEY_MANAGEMENT_PATH
                                                                                                                         + "/createCertificateOrKeyFromKeystore?keystorename=K1");

  public static final Predicate<HtmlAnchor> DELETE_KEYSTORE_ANCHOR_PREDICATE = a -> a.getHrefAttribute()
                                                                                     .startsWith(KEY_MANAGEMENT_PATH
                                                                                                 + "/deleteKeyStore");

  public static final Predicate<HtmlAnchor> DELETE_CERTIFICATE_ANCHOR_PREDICATE = a -> a.getHrefAttribute()
                                                                                        .startsWith(KEY_MANAGEMENT_PATH
                                                                                                    + "/deleteCertificate");

  public static final Predicate<HtmlAnchor> REMOVE_ABORT_ANCHOR_PREDICATE = a -> a.getHrefAttribute()
                                                                                  .startsWith(KEY_MANAGEMENT_PATH);

  public static final Predicate<HtmlAnchor> REMOVE_KEYPAIR_ANCHOR_PREDICATE = a -> a.getHrefAttribute()
                                                                                    .startsWith(KEY_MANAGEMENT_PATH
                                                                                                + "/deleteKeypair");

  private final ConfigurationService configurationService;

  @Autowired
  public KeymanagementControllerTest(ConfigurationService configurationService)
  {
    this.configurationService = configurationService;
  }

  private HtmlPage getKeyManagementPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/keymanagement"));
    HtmlPage timerConfigPage = login(loginPage);
    assertTrue(timerConfigPage.getUrl().getPath().endsWith("/keymanagement"));
    return timerConfigPage;
  }

  @BeforeEach
  public void clearConfiguration()
  {
    configurationService.saveConfiguration(new EidasMiddlewareConfig(), false);
  }

  @Test
  @SneakyThrows
  void testUploadCertificate()
  {
    assertFalse(getKeyDataOptional().isPresent());

    HtmlPage keyManagementPage = getKeyManagementPage();
    keyManagementPage = submitFormById(keyManagementPage, "CertificateUpload");

    assertValidationMessagePresent(keyManagementPage, CERTIFICATE_UPLOAD_NAME_ID, "May not be empty");

    setTextValue(keyManagementPage, CERTIFICATE_UPLOAD_NAME_ID, "C1");
    setFileUpload(keyManagementPage, CERTIFICATE_UPLOAD_FILE_INPUT_ID, TEST_CERTIFICATE_FILE);

    submitFormById(keyManagementPage, "CertificateUpload");
    Optional<EidasMiddlewareConfig.KeyData> optionalKeyData = getKeyDataOptional();
    assertTrue(optionalKeyData.isPresent());

    List<CertificateType> certificates = optionalKeyData.get().getCertificate();
    assertEquals(1, certificates.size());
    assertEquals("C1", certificates.get(0).getName());
    assertArrayEquals(getTestCertificate(), certificates.get(0).getCertificate());
  }

  @Test
  @SneakyThrows
  void testUploadKeyStore()
  {
    HtmlPage keyManagementPage = getKeyManagementPage();


    assertFalse(getKeyDataOptional().isPresent());


    keyManagementPage = submitFormById(keyManagementPage, KEY_STORE_UPLOAD_FORM_ID);

    assertValidationMessagePresent(keyManagementPage, KEYSTORE_UPLOAD_NAME_ID, "May not be empty");

    setTextValue(keyManagementPage, KEYSTORE_UPLOAD_NAME_ID, "K1");
    setPasswordValue(keyManagementPage, KEYSTORE_UPLOAD_PASSWORD_ID, TEST_KEY_STORE_PASSWORD);
    setSelectValue(keyManagementPage, KEYSTORE_UPLOAD_KEYSTORE_TYPE_ID, TEST_KEY_STORE_TYPE);

    setFileUpload(keyManagementPage, KEYSTORE_UPLOAD_FILE_ID, TEST_KEY_STORE_FILE);

    submitFormById(keyManagementPage, KEY_STORE_UPLOAD_FORM_ID);
    Optional<EidasMiddlewareConfig.KeyData> optionalKeyData = getKeyDataOptional();
    assertTrue(optionalKeyData.isPresent());

    List<KeyStoreType> keyStores = optionalKeyData.get().getKeyStore();
    assertEquals(1, keyStores.size());
    assertEquals("K1", keyStores.get(0).getName());
    assertArrayEquals(getTestKeyStoreBytes(), keyStores.get(0).getKeyStore());
  }

  @Test
  @SneakyThrows
  void testExtractCertificate()
  {
    // Prepare Config
    assertFalse(getKeyDataOptional().isPresent());
    byte[] keyStorebytes = getTestKeyStoreBytes();

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", keyStorebytes, TEST_KEY_STORE_CONFIG_TYPE, TEST_KEY_STORE_PASSWORD));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // Extract certificate
    HtmlPage keyManagementPage = getKeyManagementPage();

    Optional<HtmlAnchor> optionalExtractButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                          EXTRACT_FROM_KEYSTORE_ANCHOR_PREDICATE);
    assertOptionalIsPresent(optionalExtractButton, "Button to extract from key store is missing");

    HtmlPage extractPage = optionalExtractButton.get().click();

    // Submit for errors
    extractPage = submitFormById(extractPage, EXTRACT_CERTIFICATE_FORM_ID);
    assertValidationMessagePresent(extractPage, EXTRACT_CERTIFICATE_NAME_ID, "May not be empty");

    // Submit for success
    setTextValue(extractPage, EXTRACT_CERTIFICATE_NAME_ID, "C1");
    setSelectValue(extractPage, EXTRACT_CERTIFICATE_ALIAS_ID, TEST_CERTIFICATE_ALIAS);
    keyManagementPage = submitFormById(extractPage, EXTRACT_CERTIFICATE_FORM_ID);
    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath(), "Extraction was not successful");


    // Check config
    Optional<List<CertificateType>> certificateTypes = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getCertificate);
    assertOptionalIsPresent(certificateTypes, "Certificate has not been stored");

    List<CertificateType> storedCertificates = certificateTypes.get();
    assertEquals(1, storedCertificates.size(), "Certificate has not been stored");

    CertificateType storedCertificate = storedCertificates.get(0);
    assertEquals("C1", storedCertificate.getName());
    assertEquals("K1", storedCertificate.getKeystore());
    assertEquals(TEST_CERTIFICATE_ALIAS, storedCertificate.getAlias());

    assertArrayEquals(KeyStoreSupporter.readKeyStore(keyStorebytes,
                                                     KeyStoreSupporter.KeyStoreType.JKS,
                                                     TEST_KEY_STORE_PASSWORD)
                                       .getCertificate(TEST_CERTIFICATE_ALIAS)
                                       .getEncoded(),
                      storedCertificate.getCertificate());

    // Check confirmation
    assertEquals("Certificate created: C1",
                 keyManagementPage.getElementById("alertMSG").getTextContent(),
                 "Expected confirmation message is missing");
  }

  @Test
  @SneakyThrows
  void testExtractKeypair()
  {
    // Prepare Config
    assertFalse(getKeyDataOptional().isPresent());


    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", getTestKeyStoreBytes(), TEST_KEY_STORE_CONFIG_TYPE, TEST_KEY_STORE_PASSWORD));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // Extract certificate
    HtmlPage keyManagementPage = getKeyManagementPage();

    Optional<HtmlAnchor> optionalExtractButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                          EXTRACT_FROM_KEYSTORE_ANCHOR_PREDICATE);
    assertOptionalIsPresent(optionalExtractButton, "Button to extract from key store is missing");

    HtmlPage extractPage = optionalExtractButton.get().click();

    // Submit for errors
    extractPage = submitFormById(extractPage, EXTRACT_KEY_PAIR_FORM_ID);
    assertValidationMessagePresent(extractPage, EXTRACT_KEY_PAIR_NAME_ID, "May not be empty");

    // Submit for password error
    setTextValue(extractPage, EXTRACT_KEY_PAIR_NAME_ID, "Key1");
    setSelectValue(extractPage, EXTRACT_KEY_PAIR_ALIAS_ID, TEST_CERTIFICATE_ALIAS);
    setPasswordValue(extractPage, EXTRACT_KEY_PAIR_PASSWORD_ID, "wrong");

    extractPage = submitFormById(extractPage, EXTRACT_KEY_PAIR_FORM_ID);
    assertValidationMessagePresent(extractPage, EXTRACT_KEY_PAIR_PASSWORD_ID, "Password could be wrong");

    // Submit for success
    setTextValue(extractPage, EXTRACT_KEY_PAIR_NAME_ID, "Key1");
    setSelectValue(extractPage, EXTRACT_KEY_PAIR_ALIAS_ID, TEST_CERTIFICATE_ALIAS);
    setPasswordValue(extractPage, EXTRACT_KEY_PAIR_PASSWORD_ID, TEST_KEY_STORE_PASSWORD);

    keyManagementPage = submitFormById(extractPage, EXTRACT_KEY_PAIR_FORM_ID);
    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath(), "Extraction was not successful");

    // Check config
    Optional<List<KeyPairType>> keyPairTypes = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyPair);
    assertOptionalIsPresent(keyPairTypes, "Key pair has not been stored");

    List<KeyPairType> storedKeyPairs = keyPairTypes.get();
    assertEquals(1, storedKeyPairs.size(), "Key pair has not been stored");

    KeyPairType storedKeyPairType = storedKeyPairs.get(0);
    assertEquals("Key1", storedKeyPairType.getName());
    assertEquals("K1", storedKeyPairType.getKeyStoreName());
    assertEquals(TEST_CERTIFICATE_ALIAS, storedKeyPairType.getAlias());

    // Check confirmation
    assertEquals("Key pair created: Key1",
                 keyManagementPage.getElementById("alertMSG").getTextContent(),
                 "Expected confirmation message is missing");
  }

  @Test
  @SneakyThrows
  void testExtractKeyPairFromPKCS12()
  {
    // Prepare Config with PKCS12 key store
    assertFalse(getKeyDataOptional().isPresent());

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", FileUtils.readFileToByteArray(TEST_KEY_STORE_FILE_PKCS12),
                                 KeyStoreTypeType.PKCS_12, TEST_KEY_STORE_PASSWORD));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // Get extract page
    HtmlPage keyManagementPage = getKeyManagementPage();

    Optional<HtmlAnchor> optionalExtractButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                          EXTRACT_FROM_KEYSTORE_ANCHOR_PREDICATE);
    assertOptionalIsPresent(optionalExtractButton, "Button to extract from key store is missing");

    HtmlPage extractPage = optionalExtractButton.get().click();

    // Extract key pair, check that no password field is present
    Assertions.assertNull(extractPage.getElementById(EXTRACT_KEY_PAIR_PASSWORD_ID));
    setTextValue(extractPage, EXTRACT_KEY_PAIR_NAME_ID, "Key1");
    setSelectValue(extractPage, EXTRACT_KEY_PAIR_ALIAS_ID, TEST_CERTIFICATE_ALIAS_PKCS12);
    keyManagementPage = submitFormById(extractPage, EXTRACT_KEY_PAIR_FORM_ID);
    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath(), "Extraction was not successful");

    // Check config
    Optional<List<KeyPairType>> keyPairTypes = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyPair);
    assertOptionalIsPresent(keyPairTypes, "Key pair has not been stored");

    List<KeyPairType> storedKeyPairs = keyPairTypes.get();
    assertEquals(1, storedKeyPairs.size(), "Key pair has not been stored");

    KeyPairType storedKeyPairType = storedKeyPairs.get(0);
    assertEquals("Key1", storedKeyPairType.getName());
    assertEquals("K1", storedKeyPairType.getKeyStoreName());
    assertEquals(TEST_CERTIFICATE_ALIAS_PKCS12, storedKeyPairType.getAlias());

    // Check confirmation
    assertEquals("Key pair created: Key1",
                 keyManagementPage.getElementById("alertMSG").getTextContent(),
                 "Expected confirmation message is missing");
  }

  @Test
  @SneakyThrows
  void testRemoveKeyStore()
  {
    // Prepare Config
    assertFalse(getKeyDataOptional().isPresent());
    byte[] keyStorebytes = getTestKeyStoreBytes();

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", keyStorebytes, TEST_KEY_STORE_CONFIG_TYPE, TEST_KEY_STORE_PASSWORD));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // press Remove and abort
    HtmlPage keyManagementPage = getKeyManagementPage();

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                         DELETE_KEYSTORE_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    HtmlPage removePage = optionalRemoveButton.get().click();

    // click on abort
    final Optional<HtmlAnchor> optionalAbortButton = getHtmlAnchorByPredicate(removePage,
                                                                              REMOVE_ABORT_ANCHOR_PREDICATE);

    assertTrue(optionalAbortButton.isPresent());
    keyManagementPage = optionalAbortButton.get().click();

    /// verify nothing is removed
    Optional<List<KeyStoreType>> optionalKeyStoreTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyStore);
    assertTrue(optionalKeyStoreTypeList.isPresent());
    assertEquals(1, optionalKeyStoreTypeList.get().size());

    // click on rmeove button
    optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage, DELETE_KEYSTORE_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    removePage = optionalRemoveButton.get().click();


    // confirm remove
    keyManagementPage = submitAnyForm(removePage);

    // confirm remove
    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath());
    assertMessageAlert(keyManagementPage, "Key store removed: K1");

    // verify message and removal
    optionalKeyStoreTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyStore);
    assertTrue(optionalKeyStoreTypeList.isPresent());
    assertEquals(0, optionalKeyStoreTypeList.get().size());
  }

  @Test
  @SneakyThrows
  void testRemoveCertificate()
  {
    // Prepare Config
    assertFalse(getKeyDataOptional().isPresent());


    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getCertificate().add(new CertificateType("C1", getTestCertificate(), null, null));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // press Remove and abort
    HtmlPage keyManagementPage = getKeyManagementPage();

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                         DELETE_CERTIFICATE_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    HtmlPage removePage = optionalRemoveButton.get().click();

    // click on abort
    final Optional<HtmlAnchor> optionalAbortButton = getHtmlAnchorByPredicate(removePage,
                                                                              REMOVE_ABORT_ANCHOR_PREDICATE);

    assertTrue(optionalAbortButton.isPresent());
    keyManagementPage = optionalAbortButton.get().click();

    /// verify nothing is removed
    Optional<List<CertificateType>> optionalCertificateTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getCertificate);
    assertTrue(optionalCertificateTypeList.isPresent());
    assertEquals(1, optionalCertificateTypeList.get().size());

    // click on rmeove button
    optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage, DELETE_CERTIFICATE_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    removePage = optionalRemoveButton.get().click();


    // confirm remove
    keyManagementPage = submitAnyForm(removePage);

    // confirm remove
    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath());
    assertMessageAlert(keyManagementPage, "Certificate removed: C1");

    // verify message and removal
    optionalCertificateTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getCertificate);
    assertTrue(optionalCertificateTypeList.isPresent());
    assertEquals(0, optionalCertificateTypeList.get().size());
  }


  @Test
  @SneakyThrows
  void testRemoveKeyPair()
  {
    // Prepare Config
    assertFalse(getKeyDataOptional().isPresent());

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", getTestKeyStoreBytes(), TEST_KEY_STORE_CONFIG_TYPE, TEST_KEY_STORE_PASSWORD));
    keyData.getKeyPair().add(new KeyPairType("KP1", TEST_CERTIFICATE_ALIAS, TEST_KEY_STORE_PASSWORD, "K1"));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // press Remove and abort
    HtmlPage keyManagementPage = getKeyManagementPage();

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                         REMOVE_KEYPAIR_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    HtmlPage removePage = optionalRemoveButton.get().click();

    // click on abort
    final Optional<HtmlAnchor> optionalAbortButton = getHtmlAnchorByPredicate(removePage,
                                                                              REMOVE_ABORT_ANCHOR_PREDICATE);

    assertTrue(optionalAbortButton.isPresent());
    keyManagementPage = optionalAbortButton.get().click();

    /// verify nothing is removed
    Optional<List<KeyPairType>> optionalKeyPairTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyPair);
    assertTrue(optionalKeyPairTypeList.isPresent());
    assertEquals(1, optionalKeyPairTypeList.get().size());

    // click on rmeove button
    optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage, REMOVE_KEYPAIR_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    removePage = optionalRemoveButton.get().click();


    // confirm remove
    keyManagementPage = submitAnyForm(removePage);

    // confirm remove
    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath());
    String expectedMessage = "Key pair removed: KP1";
    assertMessageAlert(keyManagementPage, expectedMessage);

    // verify message and removal
    optionalKeyPairTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyPair);
    assertTrue(optionalKeyPairTypeList.isPresent());
    assertEquals(0, optionalKeyPairTypeList.get().size());
  }


  @Test
  @SneakyThrows
  void testRemoveReferencedKeyPair()
  {
    // Prepare Config
    assertFalse(getKeyDataOptional().isPresent());

    File keyStoreFile = TEST_KEY_STORE_FILE;
    byte[] keyStorebytes = FileUtils.readFileToByteArray(keyStoreFile);

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", keyStorebytes, TEST_KEY_STORE_CONFIG_TYPE, TEST_KEY_STORE_PASSWORD));
    keyData.getKeyPair().add(new KeyPairType("KP1", TEST_CERTIFICATE_ALIAS, TEST_KEY_STORE_PASSWORD, "K1"));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);

    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setSignatureKeyPairName("KP1");
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // press Remove and abort
    HtmlPage keyManagementPage = getKeyManagementPage();

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                         REMOVE_KEYPAIR_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    keyManagementPage = optionalRemoveButton.get().click();

    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath());
    assertErrorAlert(keyManagementPage, "Key pair KP1 is used in configuration and can not be removed");

    /// verify nothing is removed
    Optional<List<KeyPairType>> optionalKeyPairTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyPair);
    assertTrue(optionalKeyPairTypeList.isPresent());
    assertEquals(1, optionalKeyPairTypeList.get().size());
  }

  @Test
  @SneakyThrows
  void testRemoveReferencedCertificate()
  {
    // Prepare Config

    assertFalse(getKeyDataOptional().isPresent());

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getCertificate().add(new CertificateType("C1", getTestCertificate(), null, null));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);

    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setMetadataSignatureVerificationCertificateName("C1");
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // press Remove and abort
    HtmlPage keyManagementPage = getKeyManagementPage();

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                         DELETE_CERTIFICATE_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    keyManagementPage = optionalRemoveButton.get().click();

    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath());
    assertErrorAlert(keyManagementPage, "Certificate C1 is used in configuration and can not be removed");

    /// verify nothing is removed
    Optional<List<CertificateType>> optionalCertificateTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getCertificate);
    assertTrue(optionalCertificateTypeList.isPresent());
    assertEquals(1, optionalCertificateTypeList.get().size());
  }




  @Test
  @SneakyThrows
  void testRemoveKeyStoreWithReferencedCertificate()
  {
    // Prepare Config

    assertFalse(getKeyDataOptional().isPresent());

    byte[] keyStorebytes = getTestKeyStoreBytes();

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", keyStorebytes, TEST_KEY_STORE_CONFIG_TYPE, TEST_KEY_STORE_PASSWORD));
    keyData.getCertificate().add(new CertificateType("C1", getTestCertificate(), "K1", TEST_CERTIFICATE_ALIAS));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);

    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setMetadataSignatureVerificationCertificateName("C1");
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // press Remove and abort
    HtmlPage keyManagementPage = getKeyManagementPage();

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                         DELETE_KEYSTORE_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    keyManagementPage = optionalRemoveButton.get().click();

    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath());
    assertErrorAlert(keyManagementPage,
                     "Key store K1 can not be removed. Following certificates are referencing the key store: C1");

    /// verify nothing is removed
    Optional<List<CertificateType>> optionalCertificateTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getCertificate);
    assertTrue(optionalCertificateTypeList.isPresent());
    assertEquals(1, optionalCertificateTypeList.get().size());
  }


  @Test
  @SneakyThrows
  void testRemoveKeyStoreReferencedKeyPair()
  {
    // Prepare Config
    assertFalse(getKeyDataOptional().isPresent());
    byte[] keyStorebytes = getTestKeyStoreBytes();

    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType("K1", keyStorebytes, TEST_KEY_STORE_CONFIG_TYPE, TEST_KEY_STORE_PASSWORD));
    keyData.getKeyPair().add(new KeyPairType("KP1", TEST_CERTIFICATE_ALIAS, TEST_KEY_STORE_PASSWORD, "K1"));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);

    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setSignatureKeyPairName("KP1");
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // press Remove and abort
    HtmlPage keyManagementPage = getKeyManagementPage();

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = getHtmlAnchorByPredicate(keyManagementPage,
                                                                         DELETE_KEYSTORE_ANCHOR_PREDICATE);
    assertTrue(optionalRemoveButton.isPresent());
    keyManagementPage = optionalRemoveButton.get().click();

    assertEquals(KEY_MANAGEMENT_PATH, keyManagementPage.getUrl().getPath());
    assertErrorAlert(keyManagementPage,
                     "Key store K1 can not be removed. Following key pairs are referencing the key store: KP1");

    /// verify nothing is removed
    Optional<List<KeyPairType>> optionalKeyPairTypeList = getKeyDataOptional().map(EidasMiddlewareConfig.KeyData::getKeyPair);
    assertTrue(optionalKeyPairTypeList.isPresent());
    assertEquals(1, optionalKeyPairTypeList.get().size());
  }

  private Optional<EidasMiddlewareConfig.KeyData> getKeyDataOptional()
  {
    return configurationService.getConfiguration().map(EidasMiddlewareConfig::getKeyData);
  }


}
