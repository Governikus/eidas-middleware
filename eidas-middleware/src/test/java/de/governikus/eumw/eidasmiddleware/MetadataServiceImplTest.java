/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.info.BuildProperties;

import de.governikus.eumw.poseidas.server.pki.HSMServiceHolder;
import de.governikus.eumw.poseidas.service.MetadataService;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@ExtendWith(MockitoExtension.class)
class MetadataServiceImplTest
{

  /**
   * The path to the java.io.tmpdir
   */
  private static final String JAVA_IO_TMPDIR = System.getProperty("java.io.tmpdir") + "/eumw-test-directory";

  /**
   * a temp directory used to create temporary files for JUnit tests
   */
  private static String tempDirectory;

  @Mock
  BuildProperties buildProperties;

  @Mock
  HSMServiceHolder hsmServiceHolder;

  ConfigHolder configHolder;

  MetadataService metadataService;

  /**
   * In order to run builds on jenkins in parallel, the temp dirs should be unique and random.
   */
  @BeforeEach
  public void setUp() throws Exception
  {
    tempDirectory = JAVA_IO_TMPDIR + "-" + (int)(Math.random() * 1000000);
    Files.createDirectory(Paths.get(tempDirectory));
    log.trace("Generated random temp dir: {}", tempDirectory);
    prepareProperties();
    System.setProperty("spring.config.additional-location", Paths.get(tempDirectory).toString());
    configHolder = new ConfigHolder();
    metadataService = new MetadataServiceImpl(configHolder, buildProperties, hsmServiceHolder);
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

  @Test
  void whenGetMetadataCalledExpectMetadataByteArray()
  {
    Security.addProvider(new BouncyCastleProvider());
    Mockito.when(buildProperties.getVersion()).thenReturn("2.0");
    byte[] metadata = metadataService.getMetadata();
    String metadataAsString = new String(metadata);

    Assertions.assertTrue(ArrayUtils.isNotEmpty(metadata));
    Assertions.assertTrue(metadataAsString.contains("CONTACT_PERSON_COMPANY"));
    Assertions.assertTrue(metadataAsString.contains("CONTACT_PERSON_EMAIL"));
    Assertions.assertTrue(metadataAsString.contains("CONTACT_PERSON_GIVENNAME"));
    Assertions.assertTrue(metadataAsString.contains("CONTACT_PERSON_TEL"));
    Assertions.assertTrue(metadataAsString.contains("http://localhost:8080/eidas-middleware/Metadata"));
    Assertions.assertTrue(metadataAsString.contains("ORGANIZATION_DISPLAY_NAME"));
    Assertions.assertTrue(metadataAsString.contains("http://localhost:8080/eidas-middleware/RequestReceiver"));
    Assertions.assertTrue(new String(metadata).contains("2.0"));
  }

  private void prepareProperties() throws IOException, URISyntaxException
  {
    FileUtils.copyDirectory(new File(ConfigHolderTest.class.getResource("/eidasmiddlewareProperties")
                                                           .toURI()),
                            Paths.get(tempDirectory).toFile());
    String properties = IOUtils.toString(Paths.get(tempDirectory, "eidasmiddleware.properties").toUri(),
                                         StandardCharsets.UTF_8);
    String escapedTempDirectory = tempDirectory.replace("\\", "/");
    properties = properties.replace("$PATH_TO_RESOURCES$", escapedTempDirectory);
    FileUtils.writeStringToFile(Paths.get(tempDirectory, "eidasmiddleware.properties").toFile(),
                                properties,
                                StandardCharsets.UTF_8);
  }
}
