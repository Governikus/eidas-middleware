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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.function.BiConsumer;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;

import de.governikus.eumw.configuration.wizard.web.controller.AbstractWebTest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;


/**
 * author Pascal Knueppel <br>
 * created at: 04.04.2018 - 23:59 <br>
 * <br>
 */
@Slf4j
public abstract class AbstractConfigFileTest extends AbstractWebTest
{

  /**
   * we need to test several configuration setups therefore this path is just the base path to a directory
   * with several configuration directories
   */
  protected static final String CONFIGURATION_LOCATION = "/test-configurations";

  /**
   * the alias for the junit-test keystores
   */
  protected static final String KEYSTORE_ALIAS = "test";

  /**
   * a test configuration directory under the test-resources
   */
  protected static final String CONFIG_DIR_SUCCESS = "config-dir-success";

  /**
   * a test configuration directory under the test-resources
   */
  protected static final String CONFIG_DIR_EMPTY_VALUES = "config-dir-empty-values";

  /**
   * a test configuration directory under the test-resources
   */
  protected static final String CONFIG_DIR_FALSE_VALUES = "config-dir-false-values";

  /**
   * the password to open the keystores in the test-resources
   */
  protected static final String KEYSTORE_MASTER_PASSWORD = "123456";

  /**
   * used to execute a nullcheck on two variables and check for equality
   */
  protected static final BiConsumer<String, String> EQUAL_NULL_CHECK = (value1, value2) -> {
    Assertions.assertNotNull(value1);
    Assertions.assertNotNull(value2);
    Assertions.assertEquals(StringUtils.stripToEmpty(value1), StringUtils.stripToEmpty(value2));
  };

  /**
   * used to execute checks if the given values are blank.
   */
  protected static final BiConsumer<String, String> CHECK_IS_BLANK = (value1, value2) -> {
    Assertions.assertTrue(StringUtils.isBlank(value1), "value1 must be blank but was: " + value1);
    Assertions.assertTrue(StringUtils.isBlank(value2), "value2 must be blank but was: " + value2);
  };

  /**
   * during some tests we will create files with the method
   * {@link #overridePropertyInPropertiesFile(Properties, String, NameValuePair...)} in order to get the files
   * deleted again we will store the files when created within this list and will delete them again after the
   * test
   */
  private static final List<String> CREATED_FILES = new ArrayList<>();

  /**
   * deletes all created files that have been stored within {@link #CREATED_FILES}
   */
  @AfterEach
  public void deleteCreatedFiles()
  {
    CREATED_FILES.forEach(createdFile -> new File(createdFile).delete());
    CREATED_FILES.clear();
  }

  /**
   * will override a property within the properties file for a test method
   *
   * @param properties the original properties
   * @param propertiesLocation the location where the properties should be stored
   * @param nameValuePairs all properties that should be overridden
   * @return the properties with the overridden values
   */
  protected Properties overridePropertyInPropertiesFile(Properties properties,
                                                        String propertiesLocation,
                                                        NameValuePair... nameValuePairs)
  {
    for ( NameValuePair nameValuePair : nameValuePairs )
    {
      log.trace("overriding property '{}' to value '{}'", nameValuePair.getName(), nameValuePair.getValue());
      properties.setProperty(nameValuePair.getName(), nameValuePair.getValue());
    }
    try (FileOutputStream fileOutputStream = new FileOutputStream(propertiesLocation))
    {
      properties.store(fileOutputStream, null);
      CREATED_FILES.add(propertiesLocation);
      log.trace("stored properties file in location: '{}'", propertiesLocation);
    }
    catch (IOException e)
    {
      throw new IllegalStateException("could not override properties at location: " + propertiesLocation, e);
    }
    return properties;
  }

  /**
   * will load a properties file from the given URL
   *
   * @param propertiesUrl the location of the properties file to load
   * @return the properties object
   */
  protected Properties loadProperties(URL propertiesUrl)
  {
    Properties applicationProperties = new Properties();
    try (InputStream inputStream = propertiesUrl.openStream())
    {
      applicationProperties.load(inputStream);
    }
    catch (IOException e)
    {
      throw new IllegalStateException(e.getMessage(), e);
    }
    return applicationProperties;
  }

  /**
   * used as property key and value object
   */
  @Data
  @AllArgsConstructor
  protected static class NameValuePair
  {

    /**
     * the name of the value
     */
    private String name;

    /**
     * the value for the key under {@link #name}
     */
    private String value;
  }

}
