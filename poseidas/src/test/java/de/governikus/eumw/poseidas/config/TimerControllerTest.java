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
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.HtmlNumberInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.base.WebAdminTestBase;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;



/**
 * Test the admin ui for the timer config
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test timer config page")
class TimerControllerTest extends WebAdminTestBase
{

  private static final String HOURS = "hours";

  private final ConfigurationService configurationService;

  private final static String CVC_RENEWAL_HOURS_BEFORE_FIELD_ID = "hoursRefreshCvcBeforeExpiration";

  private final static String CVC_RENEWAL_VALUE_FIELD_ID = "CVC-renewal";

  private final static String CVC_RENEWAL_UNIT_FIELD_ID = "cvcRenewalUnit";

  private final static String BL_RENEWAL_VALUE_FIELD_ID = "Black-list-renewal";

  private final static String BL_RENEWAL_UNIT_FIELD_ID = "blackListRenewalUnit";

  private final static String ML_RENEWAL_VALUE_FIELD_ID = "Master-and-defect-list-renewal";

  private final static String ML_RENEWAL_UNIT_FIELD_ID = "masterDefectListRenewalUnit";

  private final static String CRL_RENEWAL_VALUE_FIELD_ID = "CRL-renewal";

  private final static String CRL_RENEWAL_UNIT_FIELD_ID = "crlRenewalUnit";

  @Autowired
  public TimerControllerTest(ConfigurationService configurationService)
  {
    this.configurationService = configurationService;
  }

  @Getter
  @AllArgsConstructor
  @RequiredArgsConstructor
  private enum Timer
  {

    CVC_RENEWAL(CVC_RENEWAL_VALUE_FIELD_ID, CVC_RENEWAL_UNIT_FIELD_ID, CVC_RENEWAL_HOURS_BEFORE_FIELD_ID),
    BL_RENEWAL(BL_RENEWAL_VALUE_FIELD_ID, BL_RENEWAL_UNIT_FIELD_ID),
    ML_RENEWAL(ML_RENEWAL_VALUE_FIELD_ID, ML_RENEWAL_UNIT_FIELD_ID),
    CRL_RENEWAL(CRL_RENEWAL_VALUE_FIELD_ID, CRL_RENEWAL_UNIT_FIELD_ID);

    private final String valueID;

    private final String unitID;

    private String hoursBeforeID;
  }

  @BeforeEach
  public void clearConfiguration()
  {
    configurationService.saveConfiguration(new EidasMiddlewareConfig(), false);
  }

  private HtmlPage getTimerConfigPage() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/timerConfiguration"));
    HtmlPage timerConfigPage = login(loginPage);
    assertTrue(timerConfigPage.getUrl().getPath().endsWith("/timerConfiguration"));
    return timerConfigPage;
  }

  @Test
  void testWrongValues() throws IOException
  {
    HtmlPage timerConfigPage = getTimerConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                   .isEmpty());

    // Test no value
    for ( Timer value : Timer.values() )
    {
      setEmptyValue(timerConfigPage, value);
    }
    timerConfigPage = submitAnyForm(timerConfigPage);


    for ( Timer value : Timer.values() )
    {
      assertValidationMessagePresent(timerConfigPage, value.valueID, "May not be empty");
      if (value == Timer.CVC_RENEWAL)
      {
        assertValidationMessagePresent(timerConfigPage, value.hoursBeforeID, "May not be empty");

      }
    }

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                   .isEmpty());
  }

  @Test
  void testCorrectValue() throws IOException
  {
    HtmlPage timerConfigPage = getTimerConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                   .isEmpty());

    // Test correct value
    for ( Timer timer : Timer.values() )
    {
      switch (timer)
      {
        case CVC_RENEWAL:
          setTimerValue(timerConfigPage, timer, 1, TimerUnit.MINUTES, 48);
          break;
        case BL_RENEWAL:
          setTimerValue(timerConfigPage, timer, 2, TimerUnit.MINUTES);
          break;
        case ML_RENEWAL:
          setTimerValue(timerConfigPage, timer, 3, TimerUnit.MINUTES);
          break;
        case CRL_RENEWAL:
          setTimerValue(timerConfigPage, timer, 4, TimerUnit.MINUTES);
          break;
        default:
          fail("Timer not represented in switch case: " + timer.name());
          break;
      }
    }

    submitAnyForm(timerConfigPage);

    // Check values
    checkValues(48, 1, TimerUnit.MINUTES, 2, TimerUnit.MINUTES, 3, TimerUnit.MINUTES, 4, TimerUnit.MINUTES);

  }

  @Test
  void testCheckDefaultValuesWhenNoTimerConfigurationPresent() throws Exception
  {
    HtmlPage timerConfigPage = getTimerConfigPage();

    assertTrue(configurationService.getConfiguration()
                                   .map(EidasMiddlewareConfig::getEidConfiguration)
                                   .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration)
                                   .isEmpty());

    Assertions.assertEquals("20", timerConfigPage.getElementById(CVC_RENEWAL_HOURS_BEFORE_FIELD_ID).asNormalizedText());
    Assertions.assertEquals("1", timerConfigPage.getElementById(CVC_RENEWAL_VALUE_FIELD_ID).asNormalizedText());
    Assertions.assertEquals(HOURS, timerConfigPage.getElementById(CVC_RENEWAL_UNIT_FIELD_ID).asNormalizedText());

    Assertions.assertEquals("15", timerConfigPage.getElementById(BL_RENEWAL_VALUE_FIELD_ID).asNormalizedText());
    Assertions.assertEquals("minutes", timerConfigPage.getElementById(BL_RENEWAL_UNIT_FIELD_ID).asNormalizedText());
    Assertions.assertEquals("2", timerConfigPage.getElementById(ML_RENEWAL_VALUE_FIELD_ID).asNormalizedText());
    Assertions.assertEquals(HOURS, timerConfigPage.getElementById(ML_RENEWAL_UNIT_FIELD_ID).asNormalizedText());

    Assertions.assertEquals("2", timerConfigPage.getElementById(CRL_RENEWAL_VALUE_FIELD_ID).asNormalizedText());
    Assertions.assertEquals(HOURS, timerConfigPage.getElementById(CRL_RENEWAL_UNIT_FIELD_ID).asNormalizedText());
  }

  private void checkValues(int cvcHoursBefore,
                           int cvcRenewValue,
                           TimerUnit cvcRenewUnit,
                           int blRenewValue,
                           TimerUnit blRenewUnit,
                           int mlRenewValue,
                           TimerUnit mlRenewUnit,
                           int crlRenewValue,
                           TimerUnit crlRenewUnit)
  {

    final Optional<TimerConfigurationType> timerConfigurationTypeOptional = configurationService.getConfiguration()
                                                                                                .map(EidasMiddlewareConfig::getEidConfiguration)
                                                                                                .map(EidasMiddlewareConfig.EidConfiguration::getTimerConfiguration);
    assertTrue(timerConfigurationTypeOptional.isPresent());
    final TimerConfigurationType timerConfigurationType = timerConfigurationTypeOptional.get();

    assertEquals(cvcHoursBefore, timerConfigurationType.getCertRenewal().getHoursRefreshCVCBeforeExpires());
    assertEquals(cvcRenewValue, timerConfigurationType.getCertRenewal().getLength());
    assertEquals(cvcRenewUnit, timerConfigurationType.getCertRenewal().getUnit());

    assertEquals(mlRenewValue, timerConfigurationType.getMasterAndDefectListRenewal().getLength());
    assertEquals(mlRenewUnit, timerConfigurationType.getMasterAndDefectListRenewal().getUnit());

    assertEquals(blRenewValue, timerConfigurationType.getBlacklistRenewal().getLength());
    assertEquals(blRenewUnit, timerConfigurationType.getBlacklistRenewal().getUnit());

    assertEquals(crlRenewValue, timerConfigurationType.getCrlRenewal().getLength());
    assertEquals(crlRenewUnit, timerConfigurationType.getCrlRenewal().getUnit());
  }

  private void setTimerValue(HtmlPage timerConfigPage, Timer timer, int value, TimerUnit unit)
  {
    setNumberValue(timerConfigPage, timer.getValueID(), value);
    setSelectValue(timerConfigPage, timer.getUnitID(), unit.name());
  }

  private void setTimerValue(HtmlPage timerConfigPage, Timer timer, int value, TimerUnit unit, int hoursBefore)
  {
    setTimerValue(timerConfigPage, timer, value, unit);
    if (timer == Timer.CVC_RENEWAL)
    {
      setNumberValue(timerConfigPage, timer.getHoursBeforeID(), hoursBefore);
    }
  }

  private void setEmptyValue(HtmlPage timerConfigPage, Timer timer)
  {
    HtmlNumberInput numberInput = (HtmlNumberInput)timerConfigPage.getElementById(timer.getValueID());
    numberInput.setText("");
    if (timer == Timer.CVC_RENEWAL)
    {
      HtmlNumberInput hoursBeforeInput = (HtmlNumberInput)timerConfigPage.getElementById(timer.getHoursBeforeID());
      hoursBeforeInput.setText("");
    }
  }
}
