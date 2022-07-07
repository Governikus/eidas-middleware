/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.io.StringReader;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.TreeSet;

import javax.validation.constraints.NotBlank;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.configuration.wizard.identifier.ApplicationPropertiesIdentifier;
import de.governikus.eumw.configuration.wizard.identifier.FileNames;
import de.governikus.eumw.configuration.wizard.identifier.HSMTypeIdentifier;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 15.02.2018 - 09:41 <br>
 * <br>
 * this class will represent the form for the view that is used to befill the application.properties
 */
@Slf4j
@Data
public class ApplicationPropertiesForm extends AbstractPropertiesConfigurationLoader
{

  /**
   * this file represents an uploaded preconfigured file that the user might have uploaded or loaded with the
   * system-start
   */
  private MultipartFile applicationPropertiesFile;

  /**
   * this port can be the http or the https port
   */
  @NotBlank
  private String serverPort;

  /**
   * This port is optional and can be used to punlish the admin interface on a different port
   */
  private String adminInterfacePort;

  /**
   * TLS keystore
   */
  private KeystoreForm serverSslKeystore;

  /**
   * the URL to the database that should be used without credentials but with configuration parameters
   */
  @NotBlank
  private String datasourceUrl;

  /**
   * the username to use with the {@link #datasourceUrl}
   */
  @NotBlank
  private String datasourceUsername;

  /**
   * the password to use with the {@link #datasourceUrl}
   */
  @NotBlank
  private String datasourcePassword;

  /**
   * username for the poseidas web-admin with {@link #adminPassword}
   */
  @NotBlank
  private String adminUsername;

  /**
   * password to access the poseidas web-admin with {@link #adminUsername}
   */
  @NotBlank
  private String adminPassword;

  /**
   * the path where the logfile should be created
   */
  @NotBlank
  private String logFile;

  /**
   * additional spring boot properties
   */
  private String additionalProperties;

  /**
   * type of hsm that sould be used
   */
  private String hsmType;

  /**
   * Days a key should be deleted, after it expired
   */
  private String hsmKeysDelete;

  /**
   * option to save a Key into a Database before its deletion
   */
  private boolean hsmKeysArchive;

  /**
   * Path to the config-file for the SUN-PKCS11-Provider
   */
  private String pkcs11ConfigProviderPath;

  /**
   * Password to login into the hsm
   */
  private String pkcs11HsmPassword;


  /**
   * {@inheritDoc}
   */
  @Override
  void readFromProperties(Properties applicationProperties)
  {
    String port = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_PORT.getPropertyName());
    this.serverPort = StringUtils.isNotBlank(port) && port.matches("\\d+") ? port : null;
    // @formatter:off
    String keystorePath = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName());
    String keystoreAlias = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName());
    String keystorePassword = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName());
    String keystoreType = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName());
    String privateKeyPassword = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName());
    // @formatter:on
    loadKeystoreSettings(FilenameUtils.getBaseName(keystorePath),
                         keystorePath,
                         keystoreType,
                         keystoreAlias,
                         keystorePassword,
                         privateKeyPassword).ifPresent(this::setServerSslKeystore);

    // @formatter:off
    this.datasourceUrl = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_URL.getPropertyName());
    this.datasourceUsername = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_USERNAME.getPropertyName());
    this.datasourcePassword = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.DATASOURCE_PASSWORD.getPropertyName());

    this.adminUsername = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_USERNAME.getPropertyName());
    this.adminPassword = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_PASSWORD.getPropertyName());

    this.logFile = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.LOGGING_FILE.getPropertyName());

    this.adminInterfacePort = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.ADMIN_INTERFACE_PORT.getPropertyName());

    this.hsmType = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.HSM_TYPE.getPropertyName());

    this.hsmKeysDelete = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.HSM_KEYS_DELETE.getPropertyName());

    this.hsmKeysArchive = Boolean.valueOf((String)applicationProperties.remove(ApplicationPropertiesIdentifier.HSM_KEYS_ARCHIVE.getPropertyName()));


    this.pkcs11ConfigProviderPath = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.PKCS11_SUN_CONFIG_PROVIDER_FILE_PATH.getPropertyName());

    this.pkcs11HsmPassword = (String)applicationProperties.remove(ApplicationPropertiesIdentifier.PKCS11_HSM_PASSWORD.getPropertyName());


    StringBuilder addPropBuilder = new StringBuilder();
    applicationProperties.forEach((key, value) -> addPropBuilder.append(key)
                                                                .append("=")
                                                                .append(value)
                                                                .append("\n"));
    this.additionalProperties = addPropBuilder.toString();
    // @formatter:on
  }

  /**
   * saves the application properties form into directory/application.properties file
   *
   * @param directory file path
   * @throws IOException
   */
  public void save(String directory) throws IOException
  {
    KeyStoreSupporter.keyStoreToFile(new File(directory),
                                     serverSslKeystore.getKeystoreName(),
                                     serverSslKeystore.getKeystore(),
                                     serverSslKeystore.getKeystorePassword());

    Properties properties = toProperties(directory);
    File file = Paths.get(directory, FileNames.APPLICATION_PROPERTIES.getFileName()).toFile();
    try (FileOutputStream fileOut = new FileOutputStream(file);)
    {
      properties.store(fileOut, null);
    }
  }

  /**
   * maps the application properties form attributes to {@link Properties}
   *
   * @return
   */
  public Properties toProperties(String pathPrefix)
  {
    Properties properties = new Properties()
    {

      @Override
      public synchronized Enumeration<Object> keys()
      {
        return Collections.enumeration(new TreeSet<>(super.keySet()));
      }
    };

    properties.setProperty(ApplicationPropertiesIdentifier.SERVER_PORT.getPropertyName(), serverPort.trim());
    properties.setProperty(ApplicationPropertiesIdentifier.ADMIN_INTERFACE_PORT.getPropertyName(),
                           adminInterfacePort.trim());
    properties.setProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE.getPropertyName(),
                           "file:" + Paths.get(pathPrefix,
                                               serverSslKeystore.getKeystoreName() + "."
                                                           + KeyStoreSupporter.KeyStoreType.valueOf(serverSslKeystore.getKeystore()
                                                                                                                     .getType())
                                                                                           .getFileExtension())
                                          .toString()
                                          .replace("\\", "/"));
    properties.setProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_PASSWORD.getPropertyName(),
                           serverSslKeystore.getKeystorePassword());
    properties.setProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_PASSWORD.getPropertyName(),
                           serverSslKeystore.getPrivateKeyPassword());
    properties.setProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEYSTORE_TYPE.getPropertyName(),
                           serverSslKeystore.getKeystore().getType());
    properties.setProperty(ApplicationPropertiesIdentifier.SERVER_SSL_KEY_ALIAS.getPropertyName(),
                           serverSslKeystore.getAlias());
    properties.setProperty(ApplicationPropertiesIdentifier.DATASOURCE_URL.getPropertyName(), datasourceUrl.trim());
    properties.setProperty(ApplicationPropertiesIdentifier.DATASOURCE_USERNAME.getPropertyName(),
                           datasourceUsername.trim());
    properties.setProperty(ApplicationPropertiesIdentifier.DATASOURCE_PASSWORD.getPropertyName(),
                           datasourcePassword);
    properties.setProperty(ApplicationPropertiesIdentifier.ADMIN_USERNAME.getPropertyName(), adminUsername.trim());
    properties.setProperty(ApplicationPropertiesIdentifier.ADMIN_PASSWORD.getPropertyName(),
                           hashIfNecessary(adminPassword));
    if (StringUtils.isNotEmpty(logFile))
    {
      properties.setProperty(ApplicationPropertiesIdentifier.LOGGING_FILE.getPropertyName(), logFile);
    }

    properties.setProperty(ApplicationPropertiesIdentifier.HSM_TYPE.getPropertyName(), hsmType);

    if (hsmType.equals(HSMTypeIdentifier.PKCS11.name()))
    {

      if (StringUtils.isNotEmpty(hsmKeysDelete))
      {
        properties.setProperty(ApplicationPropertiesIdentifier.HSM_KEYS_DELETE.getPropertyName(),
                               hsmKeysDelete.trim());
      }

      properties.setProperty(ApplicationPropertiesIdentifier.HSM_KEYS_ARCHIVE.getPropertyName(),
                             String.valueOf(hsmKeysArchive));


      properties.setProperty(ApplicationPropertiesIdentifier.PKCS11_SUN_CONFIG_PROVIDER_FILE_PATH.getPropertyName(),
                             pkcs11ConfigProviderPath.trim());

      properties.setProperty(ApplicationPropertiesIdentifier.PKCS11_HSM_PASSWORD.getPropertyName(),
                             pkcs11HsmPassword);
    }



    try
    {
      final List<String> lines = IOUtils.readLines(new StringReader(this.additionalProperties));
      for ( String line : lines )
      {
        final int seperator = line.indexOf('=');
        properties.setProperty(line.substring(0, seperator), line.substring(seperator + 1, line.length()));
      }
    }
    catch (IOException e)
    {
      log.error("Cannot read additional properties", e);
    }

    return properties;
  }

  /**
   * @see #applicationPropertiesFile
   */
  public void setApplicationPropertiesFile(MultipartFile applicationPropertiesFile)
  {
    this.applicationPropertiesFile = applicationPropertiesFile;
    if (applicationPropertiesFile != null && !applicationPropertiesFile.isEmpty())
    {
      loadConfiguration(applicationPropertiesFile);
    }
  }

  /**
   * If a previous configuration is loaded, do not hash the already hashed password
   *
   * @param adminPassword The password, may have been entered by the user in plain text or it is the already
   *          hashed password read from the previous configuration
   * @return The newly hashed password if it was in plaintext or the already hashed password from the previous
   *         configuration
   */
  private String hashIfNecessary(String adminPassword)
  {
    if (adminPassword.startsWith("$2a$10$"))
    {
      return adminPassword;
    }
    else
    {
      return BCrypt.hashpw(adminPassword, BCrypt.gensalt());
    }
  }
}
