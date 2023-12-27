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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSelect;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.KeyStoreTypeType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidasstarterkit.EidasSigner;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;



/**
 * Test the admin ui for the timer config
 */
@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test eidas config page")
class EidasControllerTest extends WebAdminTestBase
{

  private static final String PROVIDER_DOES_NOT_EXIST = "This service provider does not exist!";

  private static final String HAS_TO_BE_SELECTED = "Has to be selected";

  private static final String KEY_PAIR_DOES_NOT_EXIST = "This key pair does not exist!";

  private final ConfigurationService configurationService;

  private static final String PUBLIC_SP_SELECT_ID = "Public-service-provider";

  private static final String SERVER_URL_ID = "serverUrl";

  private static final String COUNTRY_CODE_ID = "countryCode";

  private static final String CONTACT_PERSON_COMPANY_NAME_ID = "contactPersonCompanyName";

  private static final String CONTACT_PERSON_NAME_ID = "contactPersonName";

  private static final String CONTACT_PERSON_SURNAME_ID = "contactPersonSurname";

  private static final String CONTACT_PERSON_EMAIL_ID = "contactPersonMail";

  private static final String CONTACT_PERSON_PHONE_ID = "contactPersonTel";

  private static final String ORGANIZATION_DISPLAYNAME_ID = "organizationDisplayname";

  private static final String ORGANIZATION_NAME_ID = "organizationName";

  private static final String ORGANIZATION_LANGUAGE_ID = "organizationLanguage";

  private static final String ORGANIZATION_URL_ID = "organizationUrl";

  private static final String SIGNATURE_KEYPAIR_ID = "signatureKeyPairName";

  private static final String METADATA_SIGNATURE_VERIFICATION_CERTIFICATE_ID = "metadataSignatureVerificationCertificateName";

  private static final String SIGN_METADATA_ID = "Sign-metadata";

  @MockBean
  private HSMServiceHolder hsmServiceHolder;

  @Autowired
  public EidasControllerTest(ConfigurationService configurationService)
  {
    this.configurationService = configurationService;
  }

  @BeforeEach
  public void clearConfiguration()
  {
    configurationService.saveConfiguration(new EidasMiddlewareConfig(), false);
  }

  private HtmlPage getEidasConfigPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/eidasConfiguration"));
    HtmlPage timerConfigPage = login(loginPage);
    assertTrue(timerConfigPage.getUrl().getPath().endsWith("/eidasConfiguration"));
    return timerConfigPage;
  }

  @Test
  void testWrongValues() throws IOException
  {
    HtmlPage eidasConfigPage = getEidasConfigPage();

    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());

    // Test no value
    eidasConfigPage = submitAnyForm(eidasConfigPage);

    assertValidationMessagePresent(eidasConfigPage, PUBLIC_SP_SELECT_ID, PROVIDER_DOES_NOT_EXIST, HAS_TO_BE_SELECTED);
    assertValidationMessagePresent(eidasConfigPage, SERVER_URL_ID, "May not be empty");
    assertValidationMessagePresent(eidasConfigPage, COUNTRY_CODE_ID, "A Country code has exactly two characters");

    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());
  }



  @Test
  void testCorrectValue() throws IOException
  {
    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());

    // Configure temporary service provider and key pairs
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();

    keyData.getKeyStore()
           .add(new KeyStoreType("", Files.readAllBytes(TEST_KEY_STORE_FILE.toPath()), KeyStoreTypeType.JKS, "123456"));
    keyData.getKeyPair().add(new KeyPairType("KP1", "", "", ""));
    keyData.getKeyPair().add(new KeyPairType("KP2", "jks-keystore", "123456", ""));
    keyData.getKeyPair().add(new KeyPairType("KP3", "", "", ""));
    keyData.getCertificate().add(new CertificateType("C1", null, "", ""));

    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    eidConfiguration.getServiceProvider().add(new ServiceProviderType("TestSP", true, "KP", "NONE", "NONE"));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // set values
    HtmlPage eidasConfigPage = getEidasConfigPage();


    setSelectValue(eidasConfigPage, PUBLIC_SP_SELECT_ID, "TestSP");
    setTextValue(eidasConfigPage, SERVER_URL_ID, "http://localhost:80/");
    setTextValue(eidasConfigPage, COUNTRY_CODE_ID, "DE");

    setTextValue(eidasConfigPage, CONTACT_PERSON_COMPANY_NAME_ID, "ContName");
    setTextValue(eidasConfigPage, CONTACT_PERSON_NAME_ID, "Name");
    setTextValue(eidasConfigPage, CONTACT_PERSON_SURNAME_ID, "ContSur");
    setTextValue(eidasConfigPage, CONTACT_PERSON_EMAIL_ID, "ContMail");
    setTextValue(eidasConfigPage, CONTACT_PERSON_PHONE_ID, "Conthone");

    setTextValue(eidasConfigPage, ORGANIZATION_DISPLAYNAME_ID, "OrgaDN");
    setTextValue(eidasConfigPage, ORGANIZATION_NAME_ID, "OrgaName");
    setTextValue(eidasConfigPage, ORGANIZATION_LANGUAGE_ID, "OrgaL");
    setTextValue(eidasConfigPage, ORGANIZATION_URL_ID, "OrgaUrl");

    setSelectValue(eidasConfigPage, SIGNATURE_KEYPAIR_ID, "KP2");

    setCheckboxValue(eidasConfigPage, SIGN_METADATA_ID, true);

    submitAnyForm(eidasConfigPage);

    final Optional<EidasMiddlewareConfig.EidasConfiguration> eidasConfigurationOptional = configurationService.getConfiguration()
                                                                                                              .map(EidasMiddlewareConfig::getEidasConfiguration);
    assertTrue(eidasConfigurationOptional.isPresent());
    final EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = eidasConfigurationOptional.get();

    assertEquals("TestSP", eidasConfiguration.getPublicServiceProviderName());
    assertEquals("http://localhost:80/",
                 configurationService.getConfiguration().map(EidasMiddlewareConfig::getServerUrl).orElse(""));
    assertEquals("DE", eidasConfiguration.getCountryCode());

    assertEquals("ContName", eidasConfiguration.getContactPerson().getCompany());
    assertEquals("Name", eidasConfiguration.getContactPerson().getGivenname());
    assertEquals("ContSur", eidasConfiguration.getContactPerson().getSurname());
    assertEquals("ContMail", eidasConfiguration.getContactPerson().getEmail());
    assertEquals("Conthone", eidasConfiguration.getContactPerson().getTelephone());

    assertEquals("OrgaDN", eidasConfiguration.getOrganization().getDisplayname());
    assertEquals("OrgaName", eidasConfiguration.getOrganization().getName());
    assertEquals("OrgaL", eidasConfiguration.getOrganization().getLanguage());
    assertEquals("OrgaUrl", eidasConfiguration.getOrganization().getUrl());

    assertNull(eidasConfiguration.getDecryptionKeyPairName());
    assertEquals("KP2", eidasConfiguration.getSignatureKeyPairName());

    assertTrue(eidasConfiguration.isDoSign());

  }

  @SneakyThrows
  @ParameterizedTest
  @CsvSource({"/configuration/rsa-2048.p12,rsa-2048,The key pair does not fulfill the eIDAS crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=rsa-2048 and serial 1702297893 does not meet specified minimum RSA key size of 3072.",
              "/configuration/secp224r1.p12,secp224r1,The key pair does not fulfill the eIDAS crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=secp224r1 and serial 691177073619503856166633885441189605629960653141 does not meet specified minimum EC key size of 256.",
              "/configuration/brainpoolP512r1-explicit.p12,brainpoolP512r1,The signature certificate does not meet the crypto requirements: The key pair does not fulfill the eIDAS crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=BPR-CSCA, OU=Autent, O=Governikus, L=Bremen, C=DE and serial 30727073461927801660542095644293943332594583035 does not use a named curve."})
  void testExistingInvalidKey(String invalidKeyStore, String invalidKeyStoreAlias, String expectedError)
  {
    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());

    // Prepare a configuration with an invalid key and an RSA 4096 key
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();

    byte[] invalidKeyStoreBytes = EidasControllerTest.class.getResourceAsStream(invalidKeyStore).readAllBytes();
    keyData.getKeyStore()
           .add(new KeyStoreType(invalidKeyStoreAlias, invalidKeyStoreBytes, KeyStoreTypeType.PKCS_12, "123456"));
    keyData.getKeyPair()
           .add(new KeyPairType(invalidKeyStoreAlias, invalidKeyStoreAlias, "123456", invalidKeyStoreAlias));

    byte[] validKeyStoreBytes = EidasControllerTest.class.getResourceAsStream("/configuration/keystore.p12")
                                                         .readAllBytes();
    keyData.getKeyStore()
           .add(new KeyStoreType("pkcs12-keystore", validKeyStoreBytes, KeyStoreTypeType.PKCS_12, "123456"));
    keyData.getKeyPair().add(new KeyPairType("pkcs12-keystore", "pkcs12-keystore", "123456", "pkcs12-keystore"));

    // Set the invalid key in the eidas configuration
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setSignatureKeyPairName(invalidKeyStoreAlias);

    // Add necessary data for the eidas page
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    eidConfiguration.getServiceProvider().add(new ServiceProviderType("TestSP", true, "KP", "NONE", "NONE"));
    eidasConfiguration.setCountryCode("DE");
    eidasConfiguration.setPublicServiceProviderName("TestSP");
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);
    eidasMiddlewareConfig.setKeyData(keyData);
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);
    eidasMiddlewareConfig.setServerUrl("https://localhost");
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // Open the page and check that the key is invalid
    HtmlPage eidasConfigPage = getEidasConfigPage();
    assertErrorAlert(eidasConfigPage, expectedError);

    // Verify that this can be fixed in the UI
    setSelectValue(eidasConfigPage, "signatureKeyPairName", "pkcs12-keystore");
    eidasConfigPage = submitAnyForm(eidasConfigPage);
    assertFalse(eidasConfigPage.asNormalizedText()
                               .contains("The signature certificate does not meet the crypto requirements"));
    HtmlSelect signatureKeyPairName = (HtmlSelect)eidasConfigPage.getElementById("signatureKeyPairName");
    Assertions.assertEquals("pkcs12-keystore", signatureKeyPairName.getSelectedOptions().get(0).getText());
  }

  @SneakyThrows
  @ParameterizedTest
  @CsvSource({"/configuration/rsa-2048.p12,rsa-2048,The key pair does not fulfill the eIDAS crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=rsa-2048 and serial 1702297893 does not meet specified minimum RSA key size of 3072.",
              "/configuration/secp224r1.p12,secp224r1,The key pair does not fulfill the eIDAS crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=secp224r1 and serial 691177073619503856166633885441189605629960653141 does not meet specified minimum EC key size of 256.",
              "/configuration/brainpoolP512r1-explicit.p12,brainpoolP512r1,The signature certificate does not meet the crypto requirements: The key pair does not fulfill the eIDAS crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=BPR-CSCA, OU=Autent, O=Governikus, L=Bremen, C=DE and serial 30727073461927801660542095644293943332594583035 does not use a named curve."})
  void testSelectInvalidKey(String invalidKeyStore, String invalidKeyStoreAlias, String expectedError)
  {
    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());

    // Prepare a configuration with an invalid key and an RSA 4096 key
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();

    byte[] invalidKeyStoreBytes = EidasControllerTest.class.getResourceAsStream(invalidKeyStore).readAllBytes();
    keyData.getKeyStore()
           .add(new KeyStoreType(invalidKeyStoreAlias, invalidKeyStoreBytes, KeyStoreTypeType.PKCS_12, "123456"));
    keyData.getKeyPair()
           .add(new KeyPairType(invalidKeyStoreAlias, invalidKeyStoreAlias, "123456", invalidKeyStoreAlias));

    byte[] validKeyStoreBytes = EidasControllerTest.class.getResourceAsStream("/configuration/keystore.p12")
                                                         .readAllBytes();
    keyData.getKeyStore()
           .add(new KeyStoreType("pkcs12-keystore", validKeyStoreBytes, KeyStoreTypeType.PKCS_12, "123456"));
    keyData.getKeyPair().add(new KeyPairType("pkcs12-keystore", "pkcs12-keystore", "123456", "pkcs12-keystore"));

    // Set the valid key in the eidas configuration
    EidasMiddlewareConfig.EidasConfiguration eidasConfiguration = new EidasMiddlewareConfig.EidasConfiguration();
    eidasConfiguration.setSignatureKeyPairName("pkcs12-keystore");

    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    eidConfiguration.getServiceProvider().add(new ServiceProviderType("TestSP", true, "KP", "NONE", "NONE"));
    eidasConfiguration.setCountryCode("DE");
    eidasConfiguration.setPublicServiceProviderName("TestSP");
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);
    eidasMiddlewareConfig.setKeyData(keyData);
    eidasMiddlewareConfig.setEidasConfiguration(eidasConfiguration);
    eidasMiddlewareConfig.setServerUrl("https://localhost");
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // Open the page and check that the key is valid
    HtmlPage eidasConfigPage = getEidasConfigPage();
    assertFalse(eidasConfigPage.asNormalizedText()
                               .contains("The signature certificate does not meet the crypto requirements"));

    // Select the invalid key and try to save
    setSelectValue(eidasConfigPage, "signatureKeyPairName", invalidKeyStoreAlias);
    eidasConfigPage = submitAnyForm(eidasConfigPage);

    // Check that the error message is visible
    assertValidationMessagePresent(eidasConfigPage, "signatureKeyPairName", expectedError);

    // Check that the config was not saved by reloading the page
    eidasConfigPage = getWebClient().getPage(getRequestUrl("/eidasConfiguration"));
    HtmlSelect signatureKeyPairName = (HtmlSelect)eidasConfigPage.getElementById("signatureKeyPairName");
    Assertions.assertEquals("pkcs12-keystore", signatureKeyPairName.getSelectedOptions().get(0).getText());
  }

  @SneakyThrows
  @ParameterizedTest
  @CsvSource({"/configuration/rsa-2048.p12,rsa-2048,The signature certificate in the HSM does not meet the crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=rsa-2048 and serial 1702297893 does not meet specified minimum RSA key size of 3072.",
              "/configuration/secp224r1.p12,secp224r1,The signature certificate in the HSM does not meet the crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=secp224r1 and serial 691177073619503856166633885441189605629960653141 does not meet specified minimum EC key size of 256.",
              "/configuration/brainpoolP512r1-explicit.p12,brainpoolP512r1,The signature certificate in the HSM does not meet the crypto requirements: Certificate is not valid for that purpose because of reason Certificate with subject CN=BPR-CSCA, OU=Autent, O=Governikus, L=Bremen, C=DE and serial 30727073461927801660542095644293943332594583035 does not use a named curve."})
  void testInvalidKeyInHsm(String keyStore, String alias, String expectedError)
  {
    KeyStore hsmKeyStore = KeyStoreSupporter.readKeyStore(EidasControllerTest.class.getResourceAsStream(keyStore)
                                                                                   .readAllBytes(),
                                                          KeyStoreSupporter.KeyStoreType.PKCS12,
                                                          "123456");
    KeyStore.Entry entry = hsmKeyStore.getEntry(alias, new KeyStore.PasswordProtection("123456".toCharArray()));
    hsmKeyStore.setEntry(EidasSigner.SAML_SIGNING, entry, new KeyStore.PasswordProtection("123456".toCharArray()));
    Mockito.when(hsmServiceHolder.getKeyStore()).thenReturn(hsmKeyStore);

    HtmlPage eidasConfigPage = getEidasConfigPage();
    assertErrorAlert(eidasConfigPage, expectedError);

  }
}
