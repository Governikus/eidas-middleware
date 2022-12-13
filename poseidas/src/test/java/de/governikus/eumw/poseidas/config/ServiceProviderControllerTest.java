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
import java.util.function.Predicate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.config.DvcaConfigurationType;
import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.KeyPairType;
import de.governikus.eumw.config.KeyStoreType;
import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.extern.slf4j.Slf4j;



/**
 * Test the admin ui for the service provider config
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test service provider config page")
class ServiceProviderControllerTest extends WebAdminTestBase
{

  private final ConfigurationService configurationService;

  // --------------------------Action paths and buttons--------------------------

  public static final String CREATE_PATH = ContextPaths.SERVICE_PROVIDER_PATH + "/create";

  public static final Predicate<HtmlAnchor> REMOVESTART_ANCHOR_PREDICATE = a -> a.getHrefAttribute()
                                                                                 .startsWith(ContextPaths.ADMIN_CONTEXT_PATH
                                                                                             + ContextPaths.SERVICE_PROVIDER_PATH
                                                                                             + "/remove");

  public static final Predicate<HtmlAnchor> EDIT_ANCHOR_PREDICATE = a -> a.getHrefAttribute()
                                                                          .startsWith(ContextPaths.ADMIN_CONTEXT_PATH
                                                                                      + ContextPaths.SERVICE_PROVIDER_PATH
                                                                                      + "/edit");

  public static final Predicate<HtmlAnchor> ABORT_ANCHOR_PREDICATE = a -> "/admin-interface/serviceProvider".equals(a.getHrefAttribute());


  // --------------------------Field HTML IDs--------------------------

  public static final String ALERT_MSG_HTML_ID = "alertMSG";

  private static final String NAME_HTML_ID = "Name";

  private static final String ENABLED_HTML_ID = "Active";

  private static final String DVCA_CONFIGURATION_HTML_ID = "DVCA-configuration";

  private static final String CLIENT_KEYPAIR_NAME_HTML_ID = "clientKeyPairName";

  // -----------------------Values in form input fields-----------------------

  public static final String SERVICEPROVIDER_NAME_NEW = "ServiceproviderName";

  public static final String SERVICE_PROVIDER_NAME_EDIT = "newName";

  public static final String DVCA_NAME_NEW = "DVCA2";

  public static final String DVCA_NAME_EDIT = "DVCA3";

  public static final String KEY_STORE_NAME = "K1";

  public static final String KEY_PAIR_NAME_NEW = "KP1";

  public static final String KEY_PAIR_NAME_EDIT = "KP2";

  // --------------------------Messages after action --------------------------

  public static final String THIS_DVCA_CONFIG_DOES_NOT_EXIST = "This dvca config does not exist!";

  public static final String MAY_NOT_BE_EMPTY = "May not be empty";

  public static final String SERVICE_PROVIDER_REMOVED = "Service provider deleted: " + SERVICE_PROVIDER_NAME_EDIT;

  public static final String SAVED_SERVICE_PROVIDER_SUCCESSFULLY = "Saved service provider successfully: "
                                                                   + SERVICE_PROVIDER_NAME_EDIT;

  public static final String HAS_TO_BE_SELECTED = "Has to be selected";


  @Autowired
  public ServiceProviderControllerTest(ConfigurationService configurationService)
  {
    this.configurationService = configurationService;
  }

  @BeforeEach
  public void clearConfiguration()
  {
    configurationService.saveConfiguration(new EidasMiddlewareConfig(), false);
  }

  private HtmlPage getCreateServiceproviderConfigPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl(CREATE_PATH));
    HtmlPage serviceproviderNewPage = login(loginPage);
    assertTrue(serviceproviderNewPage.getUrl().getPath().endsWith(CREATE_PATH));
    return serviceproviderNewPage;
  }

  @Test
  void testCreateServiceproviderWithWrongValues() throws IOException
  {
    HtmlPage createServiceproviderConfigPage = getCreateServiceproviderConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                   .isEmpty());

    // Test no value
    createServiceproviderConfigPage = submitAnyForm(createServiceproviderConfigPage);

    assertValidationMessagePresent(createServiceproviderConfigPage, NAME_HTML_ID, MAY_NOT_BE_EMPTY);
    assertValidationMessagePresent(createServiceproviderConfigPage,
                                   DVCA_CONFIGURATION_HTML_ID,
                                   THIS_DVCA_CONFIG_DOES_NOT_EXIST);
    assertValidationMessagePresent(createServiceproviderConfigPage, CLIENT_KEYPAIR_NAME_HTML_ID, HAS_TO_BE_SELECTED);


    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getDvcaConfiguration)
                                   .isEmpty());
  }


  @Test
  void testUserJourney() throws IOException
  {
    HtmlPage serviceproviderMainPage = createServiceprovider();
    serviceproviderMainPage = editServiceprovider(serviceproviderMainPage);
    removeServiceprovider(serviceproviderMainPage);

  }


  HtmlPage createServiceprovider() throws IOException
  {
    assertTrue(configurationService.getConfiguration().map(EidasMiddlewareConfig::getEidasConfiguration).isEmpty());

    // Configure temporary DVCA config
    DvcaConfigurationType dvcaConfig1 = new DvcaConfigurationType();
    dvcaConfig1.setName(DVCA_NAME_NEW);
    DvcaConfigurationType dvcaConfig2 = new DvcaConfigurationType();
    dvcaConfig2.setName(DVCA_NAME_EDIT);

    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    eidConfiguration.getDvcaConfiguration().addAll(List.of(dvcaConfig1, dvcaConfig2));

    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);

    // Configure temporary Keydata config
    EidasMiddlewareConfig.KeyData keyData = new EidasMiddlewareConfig.KeyData();
    keyData.getKeyStore()
           .add(new KeyStoreType(KEY_STORE_NAME, getTestKeyStoreBytes(), TEST_KEY_STORE_CONFIG_TYPE, PASSWORD));
    keyData.getKeyPair().add(new KeyPairType(KEY_PAIR_NAME_NEW, TEST_CERTIFICATE_ALIAS, PASSWORD, KEY_STORE_NAME));
    keyData.getKeyPair().add(new KeyPairType(KEY_PAIR_NAME_EDIT, TEST_CERTIFICATE_ALIAS, PASSWORD, KEY_STORE_NAME));

    eidasMiddlewareConfig.setKeyData(keyData);

    configurationService.saveConfiguration(eidasMiddlewareConfig, false);


    HtmlPage createServiceproviderPage = getCreateServiceproviderConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider)
                                   .map(List::isEmpty)
                                   .orElse(false));


    fillServiceproviderEditPgae(createServiceproviderPage,
                                SERVICEPROVIDER_NAME_NEW,
                                true,
                                DVCA_NAME_NEW,
                                KEY_PAIR_NAME_EDIT);

    HtmlPage serviceproviderMainPage = submitAnyForm(createServiceproviderPage);
    DomElement alertMSG = serviceproviderMainPage.getElementById(ALERT_MSG_HTML_ID);
    assertNotNull(alertMSG, "No confirmation message found after saving the service provider.");
    assertEquals("Saved service provider successfully: " + SERVICEPROVIDER_NAME_NEW, alertMSG.getTextContent());


    final Optional<List<ServiceProviderType>> optionalServiceproviderTypes = configurationService.getConfiguration()
                                                                                                 .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                                                 .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider);
    assertTrue(optionalServiceproviderTypes.isPresent());
    assertEquals(1, optionalServiceproviderTypes.get().size());


    verifyServiceprovider(optionalServiceproviderTypes.get().get(0), SERVICEPROVIDER_NAME_NEW, true, DVCA_NAME_NEW);

    return serviceproviderMainPage;
  }

  private void fillServiceproviderEditPgae(HtmlPage createServiceproviderPage,
                                           String name,
                                           boolean enabled,
                                           String dvcaConfigurationName,
                                           String clientKeyPairName)
  {
    setTextValue(createServiceproviderPage, NAME_HTML_ID, name);
    setCheckboxValue(createServiceproviderPage, ENABLED_HTML_ID, enabled);
    setSelectValue(createServiceproviderPage, DVCA_CONFIGURATION_HTML_ID, dvcaConfigurationName);
    setSelectValue(createServiceproviderPage, CLIENT_KEYPAIR_NAME_HTML_ID, clientKeyPairName);
  }

  private void verifyServiceprovider(ServiceProviderType serviceProviderType,
                                     String name,
                                     boolean enabled,
                                     String dvcaConfigurationName)
  {
    assertEquals(name, serviceProviderType.getName());
    assertEquals(enabled, serviceProviderType.isEnabled());
    assertEquals(dvcaConfigurationName, serviceProviderType.getDvcaConfigurationName());
  }

  HtmlPage editServiceprovider(HtmlPage serviceproviderMainPage) throws IOException
  {

    // click on edit
    final Optional<HtmlAnchor> optionaleditButton = getHtmlAnchorByPredicate(serviceproviderMainPage,
                                                                             EDIT_ANCHOR_PREDICATE);
    assertTrue(optionaleditButton.isPresent(), "Edit button on service provider index page not found.");
    HtmlPage serviceproviderEditPage = optionaleditButton.get().click();


    // change fields
    fillServiceproviderEditPgae(serviceproviderEditPage,
                                SERVICE_PROVIDER_NAME_EDIT,
                                false,
                                DVCA_NAME_EDIT,
                                KEY_PAIR_NAME_NEW);
    // submit
    serviceproviderMainPage = submitAnyForm(serviceproviderEditPage);

    assertEquals(SAVED_SERVICE_PROVIDER_SUCCESSFULLY,
                 serviceproviderMainPage.getElementById(ALERT_MSG_HTML_ID).getTextContent());
    // verify changes

    final Optional<List<ServiceProviderType>> optionalServiceproviderTypes = configurationService.getConfiguration()
                                                                                                 .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                                                 .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider);
    assertTrue(optionalServiceproviderTypes.isPresent());
    assertEquals(1, optionalServiceproviderTypes.get().size());

    verifyServiceprovider(optionalServiceproviderTypes.get().get(0), SERVICE_PROVIDER_NAME_EDIT, false, DVCA_NAME_EDIT);

    return serviceproviderMainPage;
  }

  private HtmlPage removeServiceprovider(HtmlPage serviceproviderMainPage) throws IOException
  {

    // click on remove button
    Optional<HtmlAnchor> optionalStartRemoveButton = getHtmlAnchorByPredicate(serviceproviderMainPage,
                                                                              REMOVESTART_ANCHOR_PREDICATE);

    assertTrue(optionalStartRemoveButton.isPresent(), "Remove button on service provider index page not found!");
    HtmlPage serviceproviderRemovePage = optionalStartRemoveButton.get().click();

    // click on abort
    final Optional<HtmlAnchor> optionalAbortButton = getHtmlAnchorByPredicate(serviceproviderRemovePage,
                                                                              ABORT_ANCHOR_PREDICATE);
    assertTrue(optionalAbortButton.isPresent(), "Abort button on delete service provider page not found!");
    serviceproviderMainPage = optionalAbortButton.get().click();

    /// verify nothing is removed
    Optional<List<ServiceProviderType>> optionalServiceproviderTypes = configurationService.getConfiguration()
                                                                                           .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                                           .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider);
    assertTrue(optionalServiceproviderTypes.isPresent());
    assertEquals(1, optionalServiceproviderTypes.get().size());

    // click on rmeove button
    optionalStartRemoveButton = getHtmlAnchorByPredicate(serviceproviderMainPage, REMOVESTART_ANCHOR_PREDICATE);
    assertTrue(optionalStartRemoveButton.isPresent(), "Remove button on service provider index page not found!");
    serviceproviderRemovePage = optionalStartRemoveButton.get().click();

    // confirm remove
    serviceproviderMainPage = submitAnyForm(serviceproviderRemovePage);

    // confirm remove
    assertEquals(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.SERVICE_PROVIDER_PATH,
                 serviceproviderMainPage.getUrl().getPath());
    assertNotNull(serviceproviderMainPage.getElementById(ALERT_MSG_HTML_ID));
    assertEquals(SERVICE_PROVIDER_REMOVED, serviceproviderMainPage.getElementById(ALERT_MSG_HTML_ID).getTextContent());

    // verify message and removal
    optionalServiceproviderTypes = configurationService.getConfiguration()
                                                       .map(EidasMiddlewareConfig::getEidConfiguration)
                                                       .map(EidasMiddlewareConfig.EidConfiguration::getServiceProvider);
    assertTrue(optionalServiceproviderTypes.isPresent());
    assertEquals(0, optionalServiceproviderTypes.get().size());

    return serviceproviderMainPage;
  }
}
