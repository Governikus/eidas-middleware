/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;


import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlBold;
import com.gargoylesoftware.htmlunit.html.HtmlDivision;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSpan;

import de.governikus.eumw.poseidas.config.base.TestConfiguration;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test Overview page")
class OverviewControllerTest extends ServiceProviderTestBase
{

  @Test
  void noServiceProviders() throws IOException
  {
    HtmlPage dashboardPage = openDashboard();
    Assertions.assertTrue(dashboardPage.asNormalizedText().contains("There are no service providers configured"));
  }

  private HtmlPage openDashboard() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/dashboard"));
    HtmlPage dashboardPage = login(loginPage);
    Assertions.assertTrue(dashboardPage.getUrl().getPath().endsWith("/dashboard"));
    return dashboardPage;
  }

  @Test
  void testServiceProviderInfo() throws IOException, ParseException
  {
    Mockito.when(configurationService.getConfiguration()).thenReturn(createConfiguration());
    Mockito.when(data.getPermissionDataInfo(Mockito.eq("cvcRefId"), Mockito.anyBoolean())).thenReturn(createPermissionDataInfo());

    HtmlPage dashboard = openDashboard();
    List<HtmlDivision> serviceProviderCards = dashboard.getByXPath("//div[contains(@class, 'form-group')]");
    Assertions.assertEquals(2, serviceProviderCards.size());

    assertServiceProviderInfo(serviceProviderCards,
                              SERVICE_PROVIDER,
                              INFO_MAP.get(CVC_REF_ID),
                              INFO_MAP.get(CHR),
                              INFO_MAP.get(CAR),
                              INFO_MAP.get(VALID_FROM),
                              INFO_MAP.get(VALID_UNTIL),
                              false);
    assertServiceProviderInfo(serviceProviderCards, "disabledProvider", "otherId", "", "", "", "", true);
  }

  private void assertServiceProviderInfo(List<HtmlDivision> serviceProviderCards,
                                         String serviceProviderId,
                                         String cvcRefId,
                                         String holder,
                                         String authority,
                                         String validFrom,
                                         String validUntil,
                                         boolean isInactive)
  {
    HtmlDivision serviceProviderCard = serviceProviderCards.stream()
                                                           .filter(htmlDivision -> htmlDivision.asNormalizedText()
                                                                                               .contains(serviceProviderId))
                                                           .findFirst()
                                                           .orElseThrow(() -> new IllegalStateException("Missing Service Provider on dashboard"));
    Assertions.assertEquals(isInactive, serviceProviderCard.asNormalizedText().contains("Inactive"));
    Assertions.assertEquals(serviceProviderId,
                            ((HtmlSpan)serviceProviderCard.getFirstByXPath("div/h4/span")).asNormalizedText());
    HtmlAnchor linkToDetailPage = serviceProviderCard.getFirstByXPath("div/h4/a");
    Assertions.assertTrue(linkToDetailPage.getAttribute("href").contains(serviceProviderId));
    List<HtmlDivision> infoRows = serviceProviderCard.getByXPath("div/div[contains(@class, 'row')]");
    Map<String, String> details = infoRows.stream()
                                          .collect(Collectors.toMap(htmlDivision -> ((HtmlBold)htmlDivision.getFirstByXPath("b")).asNormalizedText(),
                                                                    htmlDivision -> ((HtmlSpan)htmlDivision.getFirstByXPath("div/span")).asNormalizedText()));

    Assertions.assertEquals(5, details.size());
    Assertions.assertEquals(cvcRefId, details.get(CVC_REF_ID));
    Assertions.assertEquals(holder, details.get(CHR));
    Assertions.assertEquals(authority, details.get(CAR));
    Assertions.assertEquals(validFrom, details.get(VALID_FROM));
    Assertions.assertEquals(validUntil, details.get(VALID_UNTIL));
  }

}
