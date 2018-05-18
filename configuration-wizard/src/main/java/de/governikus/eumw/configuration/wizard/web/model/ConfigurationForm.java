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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.Observable;
import java.util.Observer;
import java.util.function.BiFunction;

import org.apache.commons.lang3.StringUtils;

import de.governikus.eumw.configuration.wizard.exceptions.ApplicationPropertiesSaveException;
import de.governikus.eumw.configuration.wizard.exceptions.MiddlewarePropertiesSaveException;
import de.governikus.eumw.configuration.wizard.exceptions.PoseidasConfigSaveException;
import de.governikus.eumw.configuration.wizard.exceptions.SavingFailedException;
import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.projectconfig.ConfigDirectory;
import de.governikus.eumw.configuration.wizard.web.model.poseidasxml.PoseidasCoreConfigForm;
import de.governikus.eumw.configuration.wizard.web.utils.ExceptionHelper;
import de.governikus.eumw.utils.key.exceptions.KeyStoreCreationFailedException;
import de.governikus.eumw.utils.xml.XmlException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 07.02.2018 - 14:34 <br>
 * <br>
 */
@Slf4j
@Data
public class ConfigurationForm implements Observer
{

  /**
   * this path gives us the location where the configuration should be saved in the end.
   */
  private ConfigDirectory configDirectory;

  /**
   * this is the directory where the configuration will eventually be saved
   */
  private String saveLocation;

  /**
   * tells us if configuration files were found at {@link #configDirectory} that have been read
   */
  private boolean configurationLoaded;

  /**
   * the configuration representing the poseidas.xml
   */
  private PoseidasCoreConfigForm poseidasConfig = new PoseidasCoreConfigForm();

  /**
   * @see ApplicationPropertiesForm
   */
  private ApplicationPropertiesForm applicationProperties = new ApplicationPropertiesForm();

  /**
   * @see EidasmiddlewarePropertiesForm
   */
  private EidasmiddlewarePropertiesForm eidasmiddlewareProperties = new EidasmiddlewarePropertiesForm();

  /**
   * @see #configDirectory
   */
  public void setConfigDirectory(ConfigDirectory configDirectory)
  {
    this.configDirectory = configDirectory;
    configDirectory.addObserver(this);
    initialize();
  }

  /**
   * will assure that the configuration gets loaded from the config directory and that the save location will
   * be set if it has not been set yet
   */
  private void initialize()
  {
    loadConfigurationFromConfigDirectory();
    if (StringUtils.isBlank(saveLocation))
    {
      this.saveLocation = configDirectory.getConfigDirectory();
    }
  }

  /**
   * will load the configuration from the given {@link #configDirectory}
   */
  public void loadConfigurationFromConfigDirectory()
  {
    BiFunction<Boolean, Boolean, Boolean> foundConfigFiles = (configLoaded,
                                                              configFileFound) -> configLoaded
                                                                                  || configFileFound;
    configurationLoaded = foundConfigFiles.apply(configurationLoaded,
                                                 poseidasConfig.loadConfiguration(getPoseidasConfigFile()));
    configurationLoaded = foundConfigFiles.apply(configurationLoaded,
                                                 applicationProperties.loadConfiguration(getApplicationPropertiesFile()));
    configurationLoaded = foundConfigFiles.apply(configurationLoaded,
                                                 eidasmiddlewareProperties.loadConfiguration(getMiddlewarePropertiesFile()));
  }

  /**
   * this method is used to check if a poseidas xml file is going to be overridden at the current save
   * location
   * 
   * @return true if the poseidas.xml does already exist
   */
  public boolean willPoseidasBeOverridden()
  {
    return getConfigurationFile(saveLocation, FileNames.POSEIDAS_XML).exists();
  }

  /**
   * this method is used to check if a application.properties file is going to be overridden at the current
   * save location
   *
   * @return true if the application.properties does already exist
   */
  public boolean willApplicationPropertiesBeOverridden()
  {
    return getConfigurationFile(saveLocation, FileNames.APPLICATION_PROPERTIES).exists();
  }

  /**
   * this method is used to check if a eidasmiddleware.properties file is going to be overridden at the
   * current save location
   *
   * @return true if the eidasmiddleware.properties does already exist
   */
  public boolean willMiddlewarePropertiesBeOverridden()
  {
    return getConfigurationFile(saveLocation, FileNames.MIDDLEWARE_PROPERTIES).exists();
  }

  /**
   * @return the file to the poseidas XML
   */
  private File getPoseidasConfigFile()
  {
    return getConfigurationFile(configDirectory.getConfigDirectory(), FileNames.POSEIDAS_XML);
  }

  /**
   * @return the file to the application.properties
   */
  private File getApplicationPropertiesFile()
  {
    return getConfigurationFile(configDirectory.getConfigDirectory(), FileNames.APPLICATION_PROPERTIES);
  }

  /**
   * @return the file to the middleware.properties
   */
  private File getMiddlewarePropertiesFile()
  {
    return getConfigurationFile(configDirectory.getConfigDirectory(), FileNames.MIDDLEWARE_PROPERTIES);
  }

  /**
   * tries to get the file under the given filename
   *
   * @param fileName the filename to look for
   * @return the file object even if it does not exist
   */
  private File getConfigurationFile(String location, FileNames fileName)
  {
    return new File(location + fileName.getFileName());
  }

  /**
   * this method will save the configuration at the desired {@link #saveLocation}
   *
   * @throws PoseidasConfigSaveException if the poseidas.xml could not be saved
   * @throws ApplicationPropertiesSaveException if the application.properties could not be saved
   * @throws MiddlewarePropertiesSaveException if the eidasmiddleware.properties could not be saved
   */
  public void saveConfiguration()
  {
    try
    {
      Files.createDirectories(Paths.get(saveLocation));
    }
    catch (IOException e)
    {
      throw new SavingFailedException("could not save configuration files for: '"
                                      + ExceptionHelper.getRootMessage(e) + "'", e);
    }
    try
    {
      getPoseidasConfig().save(saveLocation);
    }
    catch (CertificateEncodingException | XmlException e)
    {
      throw new PoseidasConfigSaveException("poseidas_error", e);
    }

    try
    {
      getApplicationProperties().save(saveLocation);
    }
    catch (IOException | KeyStoreCreationFailedException e)
    {
      throw new ApplicationPropertiesSaveException("application_error", e);
    }

    try
    {
      getEidasmiddlewareProperties().save(saveLocation,
                                          getPoseidasConfig().getServiceProvider().getEntityID());
    }
    catch (IOException | KeyStoreCreationFailedException | CertificateEncodingException e)
    {
      throw new MiddlewarePropertiesSaveException("middleware_error", e);
    }
  }

  /**
   * used in case that the value in the {@link ConfigDirectory} will be set
   * 
   * @param configDirectoryObject the {@link ConfigDirectory} instance
   * @param configDirectoryString the argument that has been changed
   */
  @Override
  public void update(Observable configDirectoryObject, Object configDirectoryString)
  {
    if (StringUtils.isNotBlank((String)configDirectoryString))
    {
      initialize();
    }
  }
}
