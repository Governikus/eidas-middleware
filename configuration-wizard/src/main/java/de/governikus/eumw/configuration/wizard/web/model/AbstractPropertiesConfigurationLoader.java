/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.web.model;

import java.io.File;
import java.io.IOException;
import java.util.Optional;
import java.util.Properties;

import org.springframework.web.multipart.MultipartFile;

import lombok.extern.slf4j.Slf4j;


/**
 * Keep base methods for working with property files in this abstract class.
 *
 * @author prange
 */
@Slf4j
public abstract class AbstractPropertiesConfigurationLoader extends AbstractConfigurationLoader
{

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean loadConfiguration(MultipartFile configurationFile)
  {
    log.trace("loading properties file '{}'", configurationFile);
    Optional<Properties> propertiesOptional;
    try
    {
      propertiesOptional = loadProperties(configurationFile.getInputStream());
    }
    catch (IOException e)
    {
      propertiesOptional = Optional.empty();
    }
    if (propertiesOptional.isPresent())
    {
      readFromProperties(propertiesOptional.get());
      return true;
    }
    else
    {
      return false;
    }
  }

  /**
   * this method will try to load an existing properties file and store its configuration within this object
   *
   * @param propertiesFile the configuration file that should be loaded
   */
  public boolean loadConfiguration(File propertiesFile)
  {
    log.trace("loading properties file '{}'", propertiesFile);
    Optional<Properties> propertiesOptional = loadProperties(propertiesFile);
    if (propertiesOptional.isPresent())
    {
      readFromProperties(propertiesOptional.get());
      return true;
    }
    else
    {
      return false;
    }
  }

  /**
   * reads the configuration from the given properties
   *
   * @param applicationProperties the properties that should hold the configuration
   */
  abstract void readFromProperties(Properties applicationProperties);
}
