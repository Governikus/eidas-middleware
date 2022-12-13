package de.governikus.eumw.poseidas.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import lombok.extern.slf4j.Slf4j;


/**
 * This class reads and creates password.properties.
 */

@Slf4j
@Component
public class PasswordHandler
{

  private static final String ADMIN_HASHED_PASSWORD = "admin.hashed.password";

  private final Properties properties = new Properties();

  @Value("${poseidas.admin.hashed.password:#{null}}")
  private String passwordInApplicationProperties;

  @Value("${poseidas.admin.username:#{null}}")
  private String usernameInApplicationProperties;

  // password.properties
  private File configFile;

  public PasswordHandler()
  {
    initializeConfigFile();
    if (configFile.exists())
    {
      updateProperties();
    }
  }


  /**
   * This method checks if a password is set in password.properties
   * 
   * @return True if password is set in password.properties.
   */
  public boolean isPasswordSet()
  {
    try
    {
      if (configFile.exists())
      {
        updateProperties();
        if (properties.containsKey(ADMIN_HASHED_PASSWORD) && !properties.getProperty(ADMIN_HASHED_PASSWORD).isBlank())
        {
          return true;
        }
        else
        {
          return migrateOldPassword();
        }
      }
      return migrateOldPassword();
    }
    catch (IOException e)
    {
      log.error("Could not migrate old password to new password.properties", e);
      return false;
    }
  }

  /**
   * @return If a password is set in application.properties.
   */
  public boolean isApplicationPropertiesPasswordSet()
  {
    return passwordInApplicationProperties != null;
  }

  /**
   * @return If a user is set in application.properties.
   */
  public boolean isApplicationPropertiesUserSet()
  {
    return usernameInApplicationProperties != null;
  }

  /**
   * Create or overwrite the password in password.properties
   * 
   * @param password New password
   * @param isMigration If the password is migrated from application.properties
   * @throws IOException If this method can't write to file system
   */
  public void updatePassword(String password, boolean isMigration) throws IOException
  {
    try (FileWriter fileWriter = new FileWriter(configFile))
    {
      if (configFile.createNewFile())
      {
        log.debug("password.application file created at: " + configFile.getAbsolutePath());
      }
      if (isMigration)
      {
        properties.setProperty(ADMIN_HASHED_PASSWORD, password);
      }
      else
      {
        properties.setProperty(ADMIN_HASHED_PASSWORD, BCrypt.hashpw(password, BCrypt.gensalt()));
      }
      properties.store(fileWriter, "");
    }
    catch (IOException e)
    {
      log.warn("Could not create or write to password.properties file in path {}! Password not set, check documentation on how to set your password",
               configFile.getAbsolutePath());
      throw new IOException("Could not create or write password.properties file in path " + configFile.getAbsolutePath()
                            + "! Password not set, Check documentation on how to set your password", e);
    }
  }

  /**
   * @return The hashed password.
   */
  public String getHashedPassword()
  {
    updateProperties();
    return properties.getProperty(ADMIN_HASHED_PASSWORD);
  }

  /**
   * Check if the given password matches the actual password in password.properties.
   * @param oldPassword The password to check against the actual password.
   * @return true when ths password matches.
   */
  public boolean verifyOldPassword(String oldPassword)
  {
    if (oldPassword != null)
    {
      return BCrypt.checkpw(oldPassword, getHashedPassword());
    }
    return false;
  }

  private boolean isDefaultPassword()
  {
    return BCrypt.checkpw("Pleasechangeme!", passwordInApplicationProperties);
  }

  public void initializeConfigFile()
  {
    File configDir;
    if (StringUtil.notNullOrEmpty(System.getProperty("spring.config.additional-location")))
    {
      configDir = new File(Utils.prepareSpringConfigLocation(System.getProperty("spring.config.additional-location")));
    }
    else if (StringUtil.notNullOrEmpty(System.getenv("SPRING_CONFIG_ADDITIONAL_LOCATION")))
    {
      configDir = new File(Utils.prepareSpringConfigLocation(System.getenv("SPRING_CONFIG_ADDITIONAL_LOCATION")));
    }
    else
    {
      configDir = new File(System.getProperty("user.dir"), "config");
    }
    configFile = new File(configDir, "password.properties");
  }

  private boolean migrateOldPassword() throws IOException
  {
    if (isApplicationPropertiesPasswordSet() && !isDefaultPassword())
    {
      updatePassword(passwordInApplicationProperties, true);
      return true;
    }
    return false;
  }

  private void updateProperties()
  {
    try (InputStream stream = new FileInputStream(configFile);)
    {
      properties.load(stream);
    }
    catch (IOException e)
    {
      log.warn("Can not load password.properties", e);
    }
  }

}
