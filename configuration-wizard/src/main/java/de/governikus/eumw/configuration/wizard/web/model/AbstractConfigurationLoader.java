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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import de.governikus.eumw.configuration.wizard.web.handler.HandlerHolder;
import de.governikus.eumw.configuration.wizard.web.utils.ExceptionHelper;
import de.governikus.eumw.utils.key.KeyReader;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import de.governikus.eumw.utils.key.exceptions.CertificateCreationException;
import de.governikus.eumw.utils.key.exceptions.KeyStoreCreationFailedException;
import lombok.extern.slf4j.Slf4j;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 28.03.2018 - 11:39 <br>
 * <br>
 */
@Slf4j
public abstract class AbstractConfigurationLoader
{

  /**
   * takes a file and will try to load the properties out of it
   *
   * @param file the property file that should be loaded if present
   * @return an empty if the file does not exist or the properties object
   */
  public Optional<Properties> loadProperties(File file)
  {
    if (!file.exists())
    {
      log.debug("no properties file found at '{}'", file);
      return Optional.empty();
    }
    try
    {
      return loadProperties(new FileInputStream(file));
    }
    catch (FileNotFoundException e)
    {
      log.error("could not create FileInputStream", e);
      return Optional.empty();
    }
  }

  /**
   * reads the properties from a given inputstream
   *
   * @param configurationInputStream the configuration input stream that should hold the properties
   * @return an empty if the stream could not be read or the properties are unreadable, the properties object
   *         else
   */
  public Optional<Properties> loadProperties(InputStream configurationInputStream)
  {
    try (InputStream inputStream = configurationInputStream)
    {
      Properties properties = new Properties();
      properties.load(inputStream);
      return Optional.of(properties);
    }
    catch (IOException e)
    {
      log.error("could not load configuration from input-stream.", e);
      return Optional.empty();
    }
  }

  /**
   * tries to load the configuration from the given multipart-file
   *
   * @param configurationFile the configuration file that should be loaded if possible
   */
  public abstract boolean loadConfiguration(MultipartFile configurationFile);

  /**
   * tries to load the keystore configuration from the given values
   *
   * @param keystorePath the path to the keystore on the host machine
   * @param keystoreType the type of the keystore on the host machine
   * @param keystoreAlias the alias of the entry that should be used
   * @param keystorePassword the password to open the keystore
   * @param privateKeyPassword the password to access the private key within the keystore
   * @return en empty if the keystore does not exist or could not be opened, the fully read keystore form else
   */
  public Optional<KeystoreForm> loadKeystoreSettings(String name,
                                                     String keystorePath,
                                                     String keystoreType,
                                                     String keystoreAlias,
                                                     String keystorePassword,
                                                     String privateKeyPassword)
  {
    File file = getFileFromPath(keystorePath).orElse(null);
    if (file == null)
    {
      log.warn("could not find given keystore at path: '{}'", keystorePath);
      return Optional.empty();
    }
    KeyStoreSupporter.KeyStoreType type = getKeystoreType(keystorePath, keystoreType);
    KeyStore keyStore;
    try
    {
      keyStore = KeyStoreSupporter.readKeyStore(file, type, keystorePassword);
    }
    catch (KeyStoreCreationFailedException ex)
    {
      log.warn("could not read keystore '{}' for: '{}'", name, ExceptionHelper.getRootMessage(ex));
      return Optional.empty();
    }
    KeystoreForm keystoreForm = KeystoreForm.builder()
                                            .keystoreName(name)
                                            .keystore(keyStore)
                                            .alias(keystoreAlias)
                                            .keystorePassword(keystorePassword)
                                            .privateKeyPassword(privateKeyPassword)
                                            .build();
    if (keystoreForm.isValid())
    {
      HandlerHolder.getKeystoreHandler().add(keystoreForm);
      return Optional.of(keystoreForm);
    }
    else
    {
      return Optional.empty();
    }
  }

  /**
   * tries to resolve the keystore type of the configured keystore
   *
   * @param keystorePath the path to the keystore, is used as fallback if {@code keystoreType} is empty
   * @param keystoreType the type of the keystore as string
   * @return the type of the given keystore, either read from {@code keystoreType} or from the file extension
   *         of {@code keystorePath}. If the type could not be figured it will default to
   *         {@link KeyStoreSupporter.KeyStoreType#JKS}
   */
  private KeyStoreSupporter.KeyStoreType getKeystoreType(String keystorePath, String keystoreType)
  {
    KeyStoreSupporter.KeyStoreType type;
    KeyStoreSupporter.KeyStoreType defaultType = KeyStoreSupporter.KeyStoreType.JKS;
    if (StringUtils.isBlank(keystoreType))
    {
      type = KeyStoreSupporter.KeyStoreType.byFileExtension(keystorePath).orElse(defaultType);
    }
    else
    {
      try
      {
        type = KeyStoreSupporter.KeyStoreType.valueOf(keystoreType.toUpperCase(Locale.ENGLISH));
      }
      catch (IllegalArgumentException ex)
      {
        log.trace(ex.getMessage());
        log.error("{} is not a valid keystore-type, defaulting to type {}", keystoreType, defaultType);
        type = defaultType;
      }
    }
    return type;
  }

  /**
   * tries to get the file that is stored under the given path
   *
   * @param path the path to get the file-object from
   * @return en empty if the path is not absolute or empty, the file object else
   */
  private Optional<File> getFileFromPath(String path)
  {
    if (StringUtils.isBlank(path))
    {
      log.trace("path is blank file cannot be found.");
      return Optional.empty();
    }
    // the third case is for being able to test this method on windows systems
    if (!path.startsWith("file:/") && path.charAt(0) != '/' && !path.matches("(file:)?[A-Z]:(/|\\\\).*"))
    {
      log.warn("path '{}' does not seem to be an absolute path", path);
      return Optional.empty();
    }

    try
    {
      URI uri = new URI(path);
      URL url = uri.toURL();
      log.trace("using valid URL to file '{}'", url.getFile());
      return Optional.of(new File(url.getFile()));
    }
    catch (URISyntaxException | MalformedURLException | IllegalArgumentException ex)
    {
      log.warn("could not parse URI for '{}'", ExceptionHelper.getRootMessage(ex));
    }

    try
    {
      Paths.get(path);
      // special fix for Linux systems. If the path matches a URL path that has failed the URL-check but
      // passes the path check the path will be treated as relative path. In order to prevent that we will
      // remove the starting "file:" string from the path to ensure we will use an absolute path
      String fixedPath = path;
      if (fixedPath.matches("file:.*"))
      {
        fixedPath = path.replaceFirst("/?file:/?", "/");
      }
      File validPathFile = new File(fixedPath);
      log.trace("using valid path to '{}' that has absolute path of: '{}'",
                fixedPath,
                validPathFile.getAbsolutePath());
      return Optional.of(validPathFile);
    }
    catch (InvalidPathException ex)
    {
      // workaround for JUnit tests on windows systems
      if (path.matches("/[A-Z]:.*"))
      {
        log.trace("path '{}' seems to be a windows-path, using workaround for JUnit tests", path);
        final String windowsPath = path.replaceFirst("/", "");
        try
        {
          Paths.get(windowsPath);
          log.trace("path '{}' is a valid windows path", windowsPath);
          return Optional.of(new File(windowsPath));
        }
        catch (InvalidPathException e)
        {
          log.trace("could not resolve path '{}' for error: {}", path, ex.getMessage());
          log.trace("could not resolve windows-path '{}' for error: {}", windowsPath, e.getMessage());
        }
      }
      else
      {
        log.trace("could not resolve path '{}' for error: {}", path, ex.getMessage());
      }
      return Optional.empty();
    }
  }

  /**
   * tries to read a X509 certificate from the given bytes
   *
   * @param name a unique name to find the certificate again within the
   *          {@link de.governikus.eumw.configuration.wizard.web.handler.CertificateHandler}
   * @param certificateBytes certificate to translate
   * @return the X509 certificate
   */
  public Optional<CertificateForm> getCertificate(String name, byte[] certificateBytes)
  {
    if (certificateBytes == null || certificateBytes.length == 0)
    {
      log.warn("{} -> field does not seem to contain certificate data", name);
      return Optional.empty();
    }
    try
    {
      CertificateForm certificateForm = CertificateForm.builder()
                                                       .certificateName(name)
                                                       .certificate(KeyReader.readX509Certificate(certificateBytes))
                                                       .build();
      if (certificateForm.isValid())
      {
        HandlerHolder.getCertificateHandler().add(certificateForm);
        return Optional.of(certificateForm);
      }
      else
      {
        return Optional.empty();
      }
    }
    catch (CertificateCreationException ex)
    {
      log.error(ex.getMessage(), ex);
      return Optional.empty();
    }
  }
}
