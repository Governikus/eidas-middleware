package de.governikus.eumw.configuration.migration;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.configuration.migration.service.ConfigurationMigrationService;
import de.governikus.eumw.utils.xml.XmlHelper;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class ConfigurationMigrationApplication
{

  public static final String WORKING_DIRECOTRY = "user.dir";

  public static final String FILE_NAME_MIDDLEWARE_CONFIG_XML = "middleware-config.xml";

  public static void main(String[] args)
  {
    if (args.length != 1)
    {
      log.error("Please start the application with the parameter containing the path to the config directory "
                + "where the eidasmiddleware.properties and POSeIDAS.xml are located. \n"
                + "For example \"java -jar configuration-migration.jar /path/to/config/folder\"");
      return;
    }
    File file = new File(System.getProperty(WORKING_DIRECOTRY), FILE_NAME_MIDDLEWARE_CONFIG_XML);
    if (checkIfFileAlreadyExist(file))
    {
      return;
    }
    ConfigurationMigrationService configurationMigrationService = new ConfigurationMigrationService();
    EidasMiddlewareConfig eidasMiddlewareConfig = configurationMigrationService.migrateOldConfig(args[0]);
    if (eidasMiddlewareConfig == null)
    {
      log.error("Cannot write eidas middleware config.");
      return;
    }
    // Write Config to user dir
    saveConfigInUserDir(eidasMiddlewareConfig, file);
  }

  private static void saveConfigInUserDir(EidasMiddlewareConfig eidasMiddlewareConfig, File file)
  {
    try (FileWriter fileWriter = new FileWriter(file, StandardCharsets.UTF_8))
    {
      fileWriter.write(XmlHelper.marshalObject(eidasMiddlewareConfig));
      log.info("Migration completed. Eidas middleware config file can be found in path {}", file.getAbsolutePath());
    }
    catch (IOException e)
    {
      log.warn("Could not write config file to {}", file.getAbsolutePath(), e);
    }
  }

  private static boolean checkIfFileAlreadyExist(File file)
  {
    if (file.exists())
    {
      log.error("A file with the name " + FILE_NAME_MIDDLEWARE_CONFIG_XML
                + " already exist. Please change the file name of the existing file or change the working directory");
      return true;
    }
    return false;
  }
}
