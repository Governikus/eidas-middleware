/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.controller;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.gargoylesoftware.htmlunit.WebAssert;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import lombok.extern.slf4j.Slf4j;


/**
 * test scenarios with multiple metadata files
 *
 * @author prange
 */
@Slf4j
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("test different scenarions with multiple metadata files")
@ActiveProfiles("test")
class MultipleMetadataFilesTest extends ConfigWizardTestBase
{

  /**
   * Test the input validation
   */
  @Test
  void testValidationMessages() throws IOException, URISyntaxException
  {
    // start the user journey until the full config is configured
    HtmlPage startPage = getWebClient().getPage(getRequestUrl(ROOT_PATH));
    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPage(applicationPropertiesPage);
    HtmlPage middlewarePage = testPoseidasPage(poseidasPage);
    HtmlPage savePage = testEidasMiddlewarePropertiesPage(middlewarePage);
    WebAssert.assertTextPresent(savePage, getMessage("button.save"));

    // go the the previous page and start messing aroung
    middlewarePage = click(savePage, Button.PREVIOUS_PAGE);

    // delete the metadata file and try to advance to the save page
    middlewarePage = click(middlewarePage, "metadata-0-button");
    middlewarePage = click(middlewarePage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(middlewarePage, getMessage("wizard.status.validation.missing.metadata"));

    // try to upload a non xml file
    HtmlFileInput metadataFileInput = (HtmlFileInput)middlewarePage.getElementById("eidasmiddlewareProperties.uploadedFile");
    URL wrongMetadataURL = getClass().getResource("/test-files/blacklist.pem");
    metadataFileInput.setFiles(Paths.get(wrongMetadataURL.toURI()).toFile());
    middlewarePage = click(middlewarePage, "metadata-upload-button");
    middlewarePage = click(middlewarePage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(middlewarePage,
                                getMessage("wizard.status.validation.incorrect.metadata", "blacklist.pem"));
  }

  /**
   * Test that it is possible to store more than one metadata file
   */
  @Test
  void testMultipleMetadataFiles() throws IOException, URISyntaxException
  {
    // start the user journey until the full config is configured
    HtmlPage startPage = getWebClient().getPage(getRequestUrl(ROOT_PATH));
    HtmlPage uploadOldConfigurationPage = testConfigDirectoryPage(startPage);
    HtmlPage applicationPropertiesPage = testUploadPage(uploadOldConfigurationPage);
    HtmlPage poseidasPage = testApplicationPropertiesPage(applicationPropertiesPage);
    HtmlPage middlewarePage = testPoseidasPage(poseidasPage);
    HtmlPage savePage = testEidasMiddlewarePropertiesPage(middlewarePage);
    WebAssert.assertTextPresent(savePage, getMessage("button.save"));

    // go the the previous page and upload a second metadata file
    middlewarePage = click(savePage, Button.PREVIOUS_PAGE);
    HtmlFileInput metadataFileInput = (HtmlFileInput)middlewarePage.getElementById("eidasmiddlewareProperties.uploadedFile");
    URL metadataURL = getClass().getResource("/test-configurations/full-config/metadata/demo.xml");
    metadataFileInput.setFiles(Paths.get(metadataURL.toURI()).toFile());
    middlewarePage = click(middlewarePage, "metadata-upload-button");
    savePage = click(middlewarePage, Button.NEXT_PAGE);
    WebAssert.assertTextPresent(savePage, getMessage("button.save"));

    // save the config
    String tempDirectory = getTempDirectory();
    setTextValue(savePage, "coreConfiguration-saveLocation", tempDirectory);
    HtmlPage finalPage = click(savePage, Button.SAVE);
    WebAssert.assertTextPresent(finalPage, getMessage("wizard.status.creation.succesful"));

    // check that both files are present
    File metadataDir = Paths.get(tempDirectory, "serviceprovider-metadata").toFile();
    File[] files = metadataDir.listFiles();
    Assertions.assertEquals(2, files.length, "Two metadata files expected");
    List<String> fileNames = Arrays.stream(files).map(File::getName).collect(Collectors.toList());
    MatcherAssert.assertThat("metadata files have the wrong names",
                             fileNames,
                             Matchers.containsInAnyOrder("metadata.xml", "demo.xml"));
  }

  /**
   * Test that it is possible to remove a metadata file from the config
   */
  @Test
  void testDeleteMetadata() throws IOException, URISyntaxException
  {
    // prepare the configuration that should be read
    Path configDir = prepareConfigDir(getClass().getResource("/test-configurations/full-config"));
    File srcMetadata = Paths.get(getClass().getResource("/test-files/metadata.xml").toURI()).toFile();
    File dstMetadata = Paths.get(configDir.toString(), "metadata", "new_metadata.xml").toFile();
    FileUtils.copyFile(srcMetadata, dstMetadata);

    // perform the user journey until the middleware page is reached
    HtmlPage startPage = getWebClient().getPage(getRequestUrl(ROOT_PATH));
    setTextValue(startPage, "configDirectory.configDirectory", configDir.toString());
    HtmlPage uploadPage = click(startPage, Button.NEXT_PAGE);
    HtmlPage applicationPage = click(uploadPage, Button.NEXT_PAGE);
    HtmlPage poseidasPage = click(applicationPage, Button.NEXT_PAGE);
    HtmlPage middlewarePage = click(poseidasPage, Button.NEXT_PAGE);

    // check that both metadata files are present
    WebAssert.assertTextPresent(middlewarePage, "demo.xml");
    WebAssert.assertTextPresent(middlewarePage, "new_metadata.xml");

    // delete the first metadata file
    middlewarePage = click(middlewarePage, "metadata-0-button");

    // save the config
    HtmlPage savePage = click(middlewarePage, Button.NEXT_PAGE);
    setTextValue(savePage,
                 "coreConfiguration-saveLocation",
                 configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString());
    HtmlPage successPage = click(savePage, Button.SAVE);
    WebAssert.assertTextPresent(successPage,
                                "The files have been created at: "
                                             + configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString());

    File metadataDir = Paths.get(configDir.resolveSibling(CONFIG_TO_BE_WRITTEN).toString(),
                                 "serviceprovider-metadata")
                            .toFile();
    File[] metadataFiles = metadataDir.listFiles();
    Assertions.assertEquals(1, metadataFiles.length, "One metadata file expected");
    Assertions.assertEquals("new_metadata.xml",
                            metadataFiles[0].getName(),
                            "'new_metadata.xml' as file name expected");
  }
}
