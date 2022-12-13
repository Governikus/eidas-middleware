/*
 * Copyright (c) 2022 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.config;

import java.io.IOException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.config.base.TestConfiguration;
import de.governikus.eumw.poseidas.config.model.ServiceProviderStatus;
import de.governikus.eumw.poseidas.server.pki.ServiceProviderStatusService;
import lombok.SneakyThrows;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test the support page")
class SupportControllerTest extends ServiceProviderTestBase
{

  private static final String REFERENCE_DATA = "Version: TEST\n" + "Number of configured service providers: 2\n"
                                               + "ServiceProviderID: serviceProvider\n" + "\t CVC is present: true\n"
                                               + "\t CVC is valid: true\n" + "\t CVC is valid until: 2022-03-23\n"
                                               + "\t URL from CVC and configuration match: true\n"
                                               + "\t TLS Certificate is linked in CVC: true\n"
                                               + "\t RSC is present: false\n" + "\t Pending RSC is present: false\n"
                                               + "ServiceProviderID: disabledProvider\n" + "\t CVC is present: false\n"
                                               + "\t RSC is present: false\n" + "\t Pending RSC is present: false";

  @MockBean
  ServiceProviderStatusService serviceProviderStatusService;

  @SneakyThrows
  @BeforeEach
  void setupMocks()
  {
    // Two service providers
    Mockito.when(configurationService.getConfiguration()).thenReturn(createConfiguration());

    // Mock ServiceProviderStatus with content only for the first service provider
    Mockito.when(serviceProviderStatusService.getServiceProviderStatus(Mockito.any())).thenAnswer(invocation -> {
      ServiceProviderType serviceProviderType = invocation.getArgument(0, ServiceProviderType.class);
      if (serviceProviderType.getName().equals(SERVICE_PROVIDER))
      {
        return createServiceProviderStatus();
      }
      else
      {
        return ServiceProviderStatus.builder().build();
      }
    });
  }

  @Test
  void testExportConfiguration() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/support"));
    HtmlPage supportPage = login(loginPage);

    HtmlAnchor downloadAnchor = (HtmlAnchor)supportPage.getElementById("download-configuration");
    Assertions.assertTrue(downloadAnchor.getHrefAttribute().contains("/downloadWithoutPrivateKeys"));
  }

  @Test
  void testEmailLink() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/support"));
    HtmlPage supportPage = login(loginPage);

    HtmlAnchor emailAnchor = (HtmlAnchor)supportPage.getElementById("send-email");
    String mailTo = emailAnchor.getHrefAttribute();
    String referenceMailToStart = "mailto:eidas-middleware@governikus.de?subject="
                                  + SupportController.encodeURIComponent("eIDAS Middleware Support Request from Unknown")
                                  + "&body=";
    Assertions.assertTrue(mailTo.contains(referenceMailToStart));
    Assertions.assertTrue(mailTo.contains(SupportController.encodeURIComponent(REFERENCE_DATA)));
  }


  @Test
  void testSupportText() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/support"));
    HtmlPage supportPage = login(loginPage);

    HtmlTextArea mailTextArea = (HtmlTextArea)supportPage.getElementById("mailText");
    String mailText = mailTextArea.getTextContent();
    Assertions.assertTrue(mailText.contains(REFERENCE_DATA));
  }
}
