/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.net.URL;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import de.governikus.eumw.configuration.wizard.projectconfig.ConfigDirectory;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 29.03.2018 - 08:38 <br>
 * <br>
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("test reading configuration files")
public class ReadConfigFilesTest extends AbstractConfigFileTest
{

  /**
   * used to manipulate the configuration path at runtime
   */
  @Autowired
  private ConfigDirectory configDirectoryBean;

  /**
   * will setup the configuration directory
   */
  @BeforeEach
  public void setupConfigurationDirectory()
  {
    URL resource = getClass().getResource(CONFIGURATION_LOCATION);
    Assertions.assertNotNull(resource, "the resource at '" + CONFIGURATION_LOCATION + "' must exist");
    configDirectoryBean.setConfigDirectory(resource.getFile());
  }

  /**
   * this test will check if the configuration files are read correctly if the configuration directory has
   * been setup at startup and will also check that it does not break the view
   */
  @ParameterizedTest // NOPMD
  @ValueSource(strings = {CONFIG_DIR_SUCCESS, CONFIG_DIR_EMPTY_VALUES, CONFIG_DIR_FALSE_VALUES})
  public void testReadFilesAtSytemStartup(String configDirExtension) throws IOException
  {
    configDirectoryBean.setConfigDirectory(configDirectoryBean.getConfigDirectory() + configDirExtension);
    HtmlPage currentPage = getWebClient().getPage(getRequestUrl("/"));
    String fieldId = "configurationLoaded";
    String successText = "Configuration has been found at path " + configDirectoryBean.getConfigDirectory()
                         + " and was successfully loaded.";
    DomElement element = currentPage.getElementById(fieldId);
    assertNotNull(element, "field " + fieldId + " should not be null.");
    assertEquals(successText, element.getTextContent(), fieldId + " should be " + successText);
  }
}
