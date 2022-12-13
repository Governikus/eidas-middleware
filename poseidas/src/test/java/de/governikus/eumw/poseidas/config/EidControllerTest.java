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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.extern.slf4j.Slf4j;



/**
 * Test the admin ui for the eID config
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test the eID config page")
class EidControllerTest extends WebAdminTestBase
{

  private final ConfigurationService configurationService;

  private final static String ALLOWED_EID_TYPES_FIELD_ID = "Allowed-eID-means";

  @Autowired
  public EidControllerTest(ConfigurationService configurationService)
  {
    this.configurationService = configurationService;
  }

  @BeforeEach
  public void clearConfiguration()
  {
    configurationService.saveConfiguration(new EidasMiddlewareConfig(), false);
  }

  private HtmlPage getEidConfigPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/eidConfiguration"));
    HtmlPage eidConfigPage = login(loginPage);
    assertTrue(eidConfigPage.getUrl().getPath().endsWith("/eidConfiguration"));
    return eidConfigPage;
  }

  @Test
  void testWrongValue() throws IOException
  {
    HtmlPage eidConfigPage = getEidConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getAllowedEidMeans)
                                   .isEmpty());

    // Test wrong value
    setTextValue(eidConfigPage, ALLOWED_EID_TYPES_FIELD_ID, "ABC");
    eidConfigPage = submitAnyForm(eidConfigPage);
    assertValidationMessagePresent(eidConfigPage,
                                   ALLOWED_EID_TYPES_FIELD_ID,
                                   "Empty for default or comma seperated list of one or two uppercase letters with no trailing comma or whitespaces");

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getAllowedEidMeans)
                                   .isEmpty());
  }

  @Test
  void testCorrectValue() throws IOException
  {
    HtmlPage eidConfigPage = getEidConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getAllowedEidMeans)
                                   .isEmpty());

    // Test correct value
    setTextValue(eidConfigPage, ALLOWED_EID_TYPES_FIELD_ID, "X");
    submitAnyForm(eidConfigPage);
    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getAllowedEidMeans)
                                   .isPresent());
    assertEquals("A,ID,UB,X",
                 configurationService.getConfiguration()
                                     .map(EidasMiddlewareConfig::getEidConfiguration)
                                     .map(EidasMiddlewareConfig.EidConfiguration::getAllowedEidMeans)
                                     .get());

  }

}
