/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Locale;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;

import com.gargoylesoftware.htmlunit.WebClient;

import de.governikus.eumw.configuration.wizard.projectconfig.ConfigDirectory;
import de.governikus.eumw.configuration.wizard.springboot.SpringBootControllerTest;
import de.governikus.eumw.configuration.wizard.web.handler.HandlerHolder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author: Pascal Knueppel <br>
 * created at: 31.01.2018 - 12:46 <br>
 * <br>
 * provides the htmlunit {@link WebClient} and will assure that the instance is open before each test and will
 * be closed after each test
 */
@Slf4j
public abstract class AbstractWebTest extends SpringBootControllerTest
{

  /**
   * The path to the java.io.tmpdir
   */
  private static final String JAVA_IO_TMPDIR = System.getProperty("java.io.tmpdir") + "/eumw-test-directory";

  /**
   * a temp directory used to create temporary files for JUnit tests
   */
  private static String tempDirectory;

  /**
   * to read the messages from the resource bundle for comparison with the text on the webpage
   */
  @Autowired
  private MessageSource messageSource;

  /**
   * will be used to execute requests with the application
   */
  @Getter
  private WebClient webClient;

  /**
   * the configuration directory must be cleared after each test
   */
  @Autowired
  private ConfigDirectory configDirectory;

  /**
   * will initialize the {@link #webClient}
   */
  @BeforeEach
  public void initWebClient()
  {
    webClient = new WebClient();
    webClient.addRequestHeader("Accept-Language", Locale.GERMAN.getLanguage());
  }

  /**
   * In order to run builds on jenkins in parallel, the temp dirs should be unique and random.
   */
  @BeforeEach
  public void generateRandomTempDir() throws IOException
  {
    tempDirectory = JAVA_IO_TMPDIR + "-" + (int)(Math.random() * 1000000);
    Files.createDirectory(Paths.get(tempDirectory));
    log.trace("Generated random temp dir: {}", tempDirectory);
  }

  /**
   * will assure that the {@link #webClient} will be closed after each test
   */
  @AfterEach
  public void destroyWebClient()
  {
    if (webClient != null)
    {
      webClient.close();
    }
  }

  /**
   * will clean the keystores and certificates that have been stored in the last test
   */
  @AfterEach
  public void cleanCertificatesAndKeystores()
  {
    HandlerHolder.getKeystoreHandler().clear();
    HandlerHolder.getCertificateHandler().clear();
  }

  /**
   * will clean configuration directory after each test-method
   */
  @AfterEach
  public void cleanConfigDirectory()
  {
    configDirectory.setConfigDirectory(null);
  }

  /**
   * deletes the temporary directory after each test
   */
  @AfterEach
  public void cleanTempDirectory()
  {
    try
    {
      FileUtils.deleteDirectory(new File(tempDirectory));
      log.trace("Deleted random temp dir: {}", tempDirectory);
    }
    catch (IOException e)
    {
      throw new IllegalStateException("could not delete directory: " + tempDirectory, e);
    }
  }

  /**
   * for lazy code reduction :-)
   */
  String getMessage(String key, String... parameters)
  {
    return messageSource.getMessage(key, parameters, Locale.GERMAN);
  }

  static String getTempDirectory()
  {
    return tempDirectory;
  }
}
