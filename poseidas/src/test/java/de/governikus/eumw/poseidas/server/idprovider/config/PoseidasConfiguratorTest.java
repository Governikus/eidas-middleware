/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;


@Slf4j
class PoseidasConfiguratorTest
{

  private static final String JAVA_IO_TMPDIR = System.getProperty("java.io.tmpdir") + "/poseidas";

  @BeforeEach
  public void setUp()
  {
    PoseidasConfigurator.reset();
  }

  @AfterAll
  static void resetFinally()
  {
    PoseidasConfigurator.reset();
    System.clearProperty("SPRING_CONFIG_ADDITIONAL_LOCATION");
    System.clearProperty("spring.config.additional-location");
  }

  @Test
  void whenGetCurrentConfigThenCurrentConfigNullWhenConfigInvalid() throws Exception
  {
    String tempDirectory = JAVA_IO_TMPDIR + "-" + (int)(Math.random() * 1000000);
    Files.createDirectory(Paths.get(tempDirectory));
    log.trace("Generated random temp dir: {}", tempDirectory);
    Path resourceDirectory = Paths.get("src", "test", "resources");
    File source = new File(resourceDirectory + "/POSeIDAS-duplicated-SP.xml");
    File dest = new File(tempDirectory + "/POSeIDAS.xml");
    Files.copy(source.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
    System.setProperty("spring.config.additional-location", Paths.get(tempDirectory).toString());
    PoseidasConfigurator instance = PoseidasConfigurator.getInstance();
    CoreConfigurationDto currentConfig = instance.getCurrentConfig();

    Assertions.assertNull(currentConfig);

    FileUtils.deleteDirectory(new File(tempDirectory));
    log.trace("Deleted random temp dir: {}", tempDirectory);
  }

  @Test
  void whenGetCurrentConfigThenCurrentConfigNullWhenFileNotFound()
  {
    Path resourceDirectory = Paths.get("src", "test");
    System.setProperty("spring.config.additional-location", resourceDirectory.toFile().getAbsolutePath());
    PoseidasConfigurator instance = PoseidasConfigurator.getInstance();
    CoreConfigurationDto currentConfig = instance.getCurrentConfig();

    Assertions.assertNull(currentConfig);
  }
}
