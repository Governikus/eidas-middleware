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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.config.CertificateType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.extern.slf4j.Slf4j;



/**
 * Test the admin ui for the timer config
 */
@Slf4j
@ExtendWith(SpringExtension.class)
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

  private static final String SERVER_URL_ID = "Server-URL";

  private static final String COUNTRY_CODE_ID = "Country-code";

  private static final String CONTACT_PERSON_COMPANY_NAME_ID = "Company-name";

  private static final String CONTACT_PERSON_NAME_ID = "Given-name";

  private static final String CONTACT_PERSON_SURNAME_ID = "Surname";

  private static final String CONTACT_PERSON_EMAIL_ID = "Email";

  private static final String CONTACT_PERSON_PHONE_ID = "Phone";

  private static final String ORGANIZATION_DISPLAYNAME_ID = "Display-name";

  private static final String ORGANIZATION_NAME_ID = "Name";

  private static final String ORGANIZATION_LANGUAGE_ID = "Language";

  private static final String ORGANIZATION_URL_ID = "URL";

  private static final String DECRYPTION_KEYPAIR_ID = "decryptionKeyPairName";

  private static final String SIGNATURE_KEYPAIR_ID = "signatureKeyPairName";

  private static final String METADATA_SIGNATURE_VERIFICATION_CERTIFICATE_ID = "metadataSignatureVerificationCertificateName";

  private static final String SIGN_METADATA_ID = "Sign-metadata";

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
    assertValidationMessagePresent(eidasConfigPage, DECRYPTION_KEYPAIR_ID, KEY_PAIR_DOES_NOT_EXIST, HAS_TO_BE_SELECTED);
    assertValidationMessagePresent(eidasConfigPage, SIGNATURE_KEYPAIR_ID, KEY_PAIR_DOES_NOT_EXIST, HAS_TO_BE_SELECTED);

    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());
  }



  @Test
  void testCorrectValue() throws IOException
  {
    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());

    // Configure temporary service provider and key pairs
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyPair().add(new KeyPairType("KP1", "", "", ""));
    keyData.getKeyPair().add(new KeyPairType("KP2", "", "", ""));
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


    setSelectValue(eidasConfigPage, DECRYPTION_KEYPAIR_ID, "KP1");
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

    assertEquals("KP1", eidasConfiguration.getDecryptionKeyPairName());
    assertEquals("KP2", eidasConfiguration.getSignatureKeyPairName());

    assertTrue(eidasConfiguration.isDoSign());

  }
}
