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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

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
import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.extern.slf4j.Slf4j;



/**
 * Test the admin ui for the dvca config
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test dvca config page")
class DvcaControllerTest extends WebAdminTestBase
{

  public static final String MAY_NOT_BE_EMPTY = "May not be empty";

  private final ConfigurationService configurationService;

  private static final String NAME_ID = "Name";

  private static final String DVCA_SERVER_CERT_ID = "serverSSLCertificateName";

  private static final String BL_TRUSTANCHOR_CERT_ID = "blackListTrustAnchorCertificateName";

  private static final String ML_TRUSTANCHOR_CERT_ID = "masterListTrustAnchorCertificateName";

  private static final String TERMINALAUTHENTICATION_SERVICE_URL_ID = "Terminal-Authentication-service-URL";

  private static final String RESTRICTED_ID_SERVICE_URL_ID = "Restricted-Identification-service-URL";

  private static final String PASSIVEAUTHENTICATION_SERVICE_URL_ID = "Passive-Authentication-service-URL";

  private static final String DVCA_CERTIFICATE_DESCRIPTION_SERVICE_URL_ID = "CVC-description-service-URL";


  @Autowired
  public DvcaControllerTest(ConfigurationService configurationService)
  {
    this.configurationService = configurationService;
  }

  @BeforeEach
  public void clearConfiguration()
  {
    configurationService.saveConfiguration(new EidasMiddlewareConfig(), false);
  }

  private HtmlPage getCreateDvcaConfigPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/dvcaConfiguration/create"));
    HtmlPage timerConfigPage = login(loginPage);
    assertTrue(timerConfigPage.getUrl().getPath().endsWith("/dvcaConfiguration/create"));
    return timerConfigPage;
  }

  @Test
  void testCreateDvcaWithWrongValues() throws IOException
  {
    HtmlPage createDvcaConfigPage = getCreateDvcaConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                                   .isEmpty());

    // Test no value
    createDvcaConfigPage = submitAnyForm(createDvcaConfigPage);

    assertValidationMessagePresent(createDvcaConfigPage, NAME_ID, MAY_NOT_BE_EMPTY);

    assertValidationMessagePresent(createDvcaConfigPage, DVCA_SERVER_CERT_ID, MAY_NOT_BE_EMPTY);
    assertValidationMessagePresent(createDvcaConfigPage, BL_TRUSTANCHOR_CERT_ID, MAY_NOT_BE_EMPTY);
    assertValidationMessagePresent(createDvcaConfigPage, ML_TRUSTANCHOR_CERT_ID, MAY_NOT_BE_EMPTY);


    assertValidationMessagePresent(createDvcaConfigPage, TERMINALAUTHENTICATION_SERVICE_URL_ID, MAY_NOT_BE_EMPTY);
    assertValidationMessagePresent(createDvcaConfigPage, RESTRICTED_ID_SERVICE_URL_ID, MAY_NOT_BE_EMPTY);
    assertValidationMessagePresent(createDvcaConfigPage, PASSIVEAUTHENTICATION_SERVICE_URL_ID, MAY_NOT_BE_EMPTY);
    assertValidationMessagePresent(createDvcaConfigPage, DVCA_CERTIFICATE_DESCRIPTION_SERVICE_URL_ID, MAY_NOT_BE_EMPTY);


    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                                   .isEmpty());
  }


  @Test
  void testUserJourney() throws IOException
  {
    HtmlPage dvcaConfigMainPage = createDvcaConfig();
    dvcaConfigMainPage = editDvcaConfig(dvcaConfigMainPage);
    removeDvcaConfig(dvcaConfigMainPage);

  }


  HtmlPage createDvcaConfig() throws IOException
  {
    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());

    // Configure temporary service provider and key pairs
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    final byte[] certificate = DvcaControllerTest.class.getResourceAsStream("/configuration/jks-keystore.cer")
                                                       .readAllBytes();
    keyData.getCertificate().add(new CertificateType("C1", certificate, "", ""));
    keyData.getCertificate().add(new CertificateType("C2", certificate, "", ""));
    keyData.getCertificate().add(new CertificateType("C3", certificate, "", ""));
    keyData.getCertificate().add(new CertificateType("C4", certificate, "", ""));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setKeyData(keyData);
    configurationService.saveConfiguration(eidasMiddlewareConfig, false);

    // set values
    HtmlPage createDvcaConfigPage = getCreateDvcaConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                                   .isEmpty());

    fillDvcaEditPgae(createDvcaConfigPage,
                     "DvcaConfigName",
                     "C2",
                     "C3",
                     "C4",
                     "https://termauth:80",
                     "https://restricted:80",
                     "https://passive:80",
                     "https://certdesc:80");

    HtmlPage dvcaConfigMainPage = submitAnyForm(createDvcaConfigPage);
    assertEquals("DVCA configuration saved: DvcaConfigName",
                 dvcaConfigMainPage.getElementById("alertMSG").getTextContent());


    final Optional<List<DvcaConfigurationType>> optionalDvcaConfigurationTypes = configurationService.getConfiguration()
                                                                                                     .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                                                     .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration);
    assertTrue(optionalDvcaConfigurationTypes.isPresent());
    assertEquals(1, optionalDvcaConfigurationTypes.get().size());


    verifyDvcaConfig(optionalDvcaConfigurationTypes.get().get(0),
                     "DvcaConfigName",
                     "C2",
                     "C3",
                     "C4",
                     "https://termauth:80",
                     "https://restricted:80",
                     "https://passive:80",
                     "https://certdesc:80");

    return dvcaConfigMainPage;
  }

  private void fillDvcaEditPgae(HtmlPage createDvcaConfigPage,
                                String name,
                                String dvcaServerCert,
                                String blTrustanchor,
                                String mlTrustanchor,
                                String termAuthUrl,
                                String restricedIdUrl,
                                String passiveAuthUrl,
                                String dvcaDescUrl)
  {
    setTextValue(createDvcaConfigPage, NAME_ID, name);

    setSelectValue(createDvcaConfigPage, DVCA_SERVER_CERT_ID, dvcaServerCert);
    setSelectValue(createDvcaConfigPage, BL_TRUSTANCHOR_CERT_ID, blTrustanchor);
    setSelectValue(createDvcaConfigPage, ML_TRUSTANCHOR_CERT_ID, mlTrustanchor);

    setTextValue(createDvcaConfigPage, TERMINALAUTHENTICATION_SERVICE_URL_ID, termAuthUrl);
    setTextValue(createDvcaConfigPage, RESTRICTED_ID_SERVICE_URL_ID, restricedIdUrl);
    setTextValue(createDvcaConfigPage, PASSIVEAUTHENTICATION_SERVICE_URL_ID, passiveAuthUrl);
    setTextValue(createDvcaConfigPage, DVCA_CERTIFICATE_DESCRIPTION_SERVICE_URL_ID, dvcaDescUrl);

  }

  private void verifyDvcaConfig(DvcaConfigurationType dvcaConfigurationType,
                                String name,
                                String dvcaServerCert,
                                String blTrustanchor,
                                String mlTrustanchor,
                                String termAuthUrl,
                                String restricedIdUrl,
                                String passiveAuthUrl,
                                String dvcaDescUrl)
  {
    assertEquals(name, dvcaConfigurationType.getName());

    assertEquals(dvcaServerCert, dvcaConfigurationType.getServerSSLCertificateName());
    assertEquals(blTrustanchor, dvcaConfigurationType.getBlackListTrustAnchorCertificateName());
    assertEquals(mlTrustanchor, dvcaConfigurationType.getMasterListTrustAnchorCertificateName());

    assertEquals(termAuthUrl, dvcaConfigurationType.getTerminalAuthServiceUrl());
    assertEquals(restricedIdUrl, dvcaConfigurationType.getRestrictedIdServiceUrl());
    assertEquals(passiveAuthUrl, dvcaConfigurationType.getPassiveAuthServiceUrl());
    assertEquals(dvcaDescUrl, dvcaConfigurationType.getDvcaCertificateDescriptionServiceUrl());

  }

  HtmlPage editDvcaConfig(HtmlPage dvcaConfigMainPage) throws IOException
  {

    // click on edit
    final Optional<HtmlAnchor> optionaleditButton = dvcaConfigMainPage.getElementsByTagName("a")
                                                                      .parallelStream()
                                                                      .map(HtmlAnchor.class::cast)
                                                                      .filter(a -> a.getHrefAttribute()
                                                                                    .startsWith("/admin-interface/dvcaConfiguration/edit"))
                                                                      .findFirst();
    assertTrue(optionaleditButton.isPresent());
    HtmlPage dvcaConfigEditPage = optionaleditButton.get().click();

    // change fields
    fillDvcaEditPgae(dvcaConfigEditPage,
                     "newName",
                     "C1",
                     "C1",
                     "C1",
                     "http://new1:80",
                     "http://new2:80",
                     "http://new3:80",
                     "http://new4:80");
    // submit
    dvcaConfigMainPage = submitAnyForm(dvcaConfigEditPage);

    assertEquals("DVCA configuration saved: newName", dvcaConfigMainPage.getElementById("alertMSG").getTextContent());
    // verify changes

    final Optional<List<DvcaConfigurationType>> optionalDvcaConfigurationTypes = configurationService.getConfiguration()
                                                                                                     .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                                                     .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration);
    assertTrue(optionalDvcaConfigurationTypes.isPresent());
    assertEquals(1, optionalDvcaConfigurationTypes.get().size());

    verifyDvcaConfig(optionalDvcaConfigurationTypes.get().get(0),
                     "newName",
                     "C1",
                     "C1",
                     "C1",
                     "http://new1:80",
                     "http://new2:80",
                     "http://new3:80",
                     "http://new4:80");

    return dvcaConfigMainPage;
  }

  private HtmlPage removeDvcaConfig(HtmlPage dvcaConfigMainPage) throws IOException
  {

    // click on remove button
    Optional<HtmlAnchor> optionalRemoveButton = dvcaConfigMainPage.getElementsByTagName("a")
                                                                  .parallelStream()
                                                                  .map(HtmlAnchor.class::cast)
                                                                  .filter(a -> a.getHrefAttribute()
                                                                                .startsWith("/admin-interface/dvcaConfiguration/remove"))
                                                                  .findFirst();
    assertTrue(optionalRemoveButton.isPresent());
    HtmlPage dvcaConfigRemovePage = optionalRemoveButton.get().click();

    // click on abort
    final Optional<HtmlAnchor> optionalAbortButton = dvcaConfigRemovePage.getElementsByTagName("a")
                                                                         .parallelStream()
                                                                         .map(HtmlAnchor.class::cast)
                                                                         .filter(a -> "/admin-interface/dvcaConfiguration".equals(a.getHrefAttribute()))
                                                                         .findFirst();
    assertTrue(optionalAbortButton.isPresent());
    dvcaConfigMainPage = optionalAbortButton.get().click();

    /// verify nothing is removed
    Optional<List<DvcaConfigurationType>> optionalDvcaConfigurationTypes = configurationService.getConfiguration()
                                                                                               .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                                               .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration);
    assertTrue(optionalDvcaConfigurationTypes.isPresent());
    assertEquals(1, optionalDvcaConfigurationTypes.get().size());

    // click on rmeove button
    optionalRemoveButton = dvcaConfigMainPage.getElementsByTagName("a")
                                             .parallelStream()
                                             .map(HtmlAnchor.class::cast)
                                             .filter(a -> a.getHrefAttribute()
                                                           .startsWith("/admin-interface/dvcaConfiguration/remove"))
                                             .findFirst();
    assertTrue(optionalRemoveButton.isPresent());
    dvcaConfigRemovePage = optionalRemoveButton.get().click();


    // confirm remove
    optionalRemoveButton = dvcaConfigRemovePage.getElementsByTagName("a")
                                               .parallelStream()
                                               .map(HtmlAnchor.class::cast)
                                               .filter(a -> a.getHrefAttribute()
                                                             .startsWith("/admin-interface/dvcaConfiguration/remove")
                                                            && a.getHrefAttribute().endsWith("?yes"))
                                               .findFirst();
    assertTrue(optionalRemoveButton.isPresent());
    dvcaConfigMainPage = optionalRemoveButton.get().click();

    // confirm remove
    assertEquals("/admin-interface/dvcaConfiguration", dvcaConfigMainPage.getUrl().getPath());
    assertNotNull(dvcaConfigMainPage.getElementById("alertMSG"));
    assertEquals("Dvca configuration removed: newName", dvcaConfigMainPage.getElementById("alertMSG").getTextContent());

    // verify message and removal
    optionalDvcaConfigurationTypes = configurationService.getConfiguration()
                                                         .map(EidasMiddlewareConfig::getEidConfiguration)
                                                         .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration);
    assertTrue(optionalDvcaConfigurationTypes.isPresent());
    assertEquals(0, optionalDvcaConfigurationTypes.get().size());

    return dvcaConfigMainPage;
  }
}
