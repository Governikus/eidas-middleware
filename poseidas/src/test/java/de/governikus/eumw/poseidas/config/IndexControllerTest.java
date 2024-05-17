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

import de.governikus.eumw.eidascommon.ContextPaths;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.poseidas.config.base.TestConfiguration;


@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"server.servlet.context-path=/"})
@Import(TestConfiguration.class)
@DisplayName("Test Index page")
class IndexControllerTest extends ServiceProviderTestBase
{

  @Test
  void openIndex() throws IOException
  {
    HtmlPage loginPage = getWebClient().getPage(getRequestUrl("/"));
    HtmlPage dashboardPage = login(loginPage);
    Assertions.assertEquals(ContextPaths.ADMIN_CONTEXT_PATH + ContextPaths.DASHBOARD, dashboardPage.getUrl().getPath());
  }

}
