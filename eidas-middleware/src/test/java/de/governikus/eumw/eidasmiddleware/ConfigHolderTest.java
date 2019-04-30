/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.utils.key.KeyStoreSupporter;
import lombok.extern.slf4j.Slf4j;


/**
 * Tests for the configuration holder
 */
@ExtendWith(SpringExtension.class)
@Slf4j
public class ConfigHolderTest
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
   * Test that the values from the properties file are properly parsed
   */
  @Test
  public void testProperties() throws IOException, URISyntaxException, GeneralSecurityException
  {
    prepareProperties();
    System.setProperty("spring.config.additional-location", Paths.get(tempDirectory).toString());
    ConfigHolder configHolder = new ConfigHolder();

    // Check the simple text based property values
    testSimpleProperties(configHolder);

    // Check the sign key store
    KeyStore keyStore = KeyStoreSupporter.readKeyStore(Paths.get(tempDirectory, "middleware-sign.p12")
                                                            .toFile(),
                                                       "123456");
    PrivateKey key = (PrivateKey)keyStore.getKey("middleware-sign", "123456".toCharArray());
    X509Certificate[] chain = {(X509Certificate)keyStore.getCertificate("middleware-sign")};
    Utils.X509KeyPair originalKeyPair = new Utils.X509KeyPair(key, chain);
    Assertions.assertEquals(originalKeyPair, configHolder.getAppSignatureKeyPair());

    // Check the metadata signature certificate
    Assertions.assertEquals(chain[0], configHolder.getMetadataSignatureCert());

    // Check the crypt certificate
    KeyStore cryptKeyStore = KeyStoreSupporter.readKeyStore(Paths.get(tempDirectory, "middleware-crypt.jks")
                                                                 .toFile(),
                                                            "123456");
    Certificate originalCertificate = KeyStoreSupporter.getCertificate(cryptKeyStore, "middleware-crypt")
                                                       .get();
    Assertions.assertEquals(originalCertificate, configHolder.getDecryptionCert());

    // Check the metadata directory
    Assertions.assertEquals(Paths.get(tempDirectory, "metadataDirectory").toFile(),
                            configHolder.getProviderConfigDir());
  }

  /**
   * Test the simple text value properties
   */
  private void testSimpleProperties(ConfigHolder configHolder)
  {
    Assertions.assertEquals(ConfigHolder.KEY_COUNTRYCODE, configHolder.getCountryCode());
    Assertions.assertEquals("http://localhost:8080/eidas-middleware",
                            configHolder.getServerURLWithContextPath());
    Assertions.assertEquals(ConfigHolder.KEY_CONTACT_PERSON_COMPANY,
                            configHolder.getContactPerson().getCompany());
    Assertions.assertEquals(ConfigHolder.KEY_CONTACT_PERSON_EMAIL,
                            configHolder.getContactPerson().getEmail());
    Assertions.assertEquals(ConfigHolder.KEY_CONTACT_PERSON_GIVENNAME,
                            configHolder.getContactPerson().getGivenName());
    Assertions.assertEquals(ConfigHolder.KEY_CONTACT_PERSON_SURNAME,
                            configHolder.getContactPerson().getSurName());
    Assertions.assertEquals(ConfigHolder.KEY_CONTACT_PERSON_TEL, configHolder.getContactPerson().getTel());
    Assertions.assertEquals(ConfigHolder.KEY_ENTITYID_INT, configHolder.getEntityIDInt());
    Assertions.assertEquals(ConfigHolder.KEY_ORGANIZATION_DISPLAY_NAME,
                            configHolder.getOrganization().getDisplayName());
    Assertions.assertEquals(ConfigHolder.KEY_ORGANIZATION_LANG, configHolder.getOrganization().getLangId());
    Assertions.assertEquals(ConfigHolder.KEY_ORGANIZATION_NAME, configHolder.getOrganization().getName());
    Assertions.assertEquals(ConfigHolder.KEY_ORGANIZATION_URL, configHolder.getOrganization().getUrl());
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

  /**
   * Make sure that trailing slashes are removed from the SERVER_URL property
   */
  @Test
  public void testServerUrl()
  {
    Properties properties = new Properties();
    String serverUrl = "https://middleware";
    properties.setProperty(ConfigHolder.KEY_SERVER_URL, serverUrl);
    ConfigHolder configHolder = new ConfigHolder(properties);
    Assertions.assertEquals(serverUrl + ContextPaths.EIDAS_CONTEXT_PATH,
                            configHolder.getServerURLWithContextPath());

    serverUrl = "https://middleware:8443";
    properties.setProperty(ConfigHolder.KEY_SERVER_URL, serverUrl);
    configHolder = new ConfigHolder(properties);
    Assertions.assertEquals(serverUrl + ContextPaths.EIDAS_CONTEXT_PATH,
                            configHolder.getServerURLWithContextPath());

    properties.setProperty(ConfigHolder.KEY_SERVER_URL, serverUrl + "/");
    configHolder = new ConfigHolder(properties);
    Assertions.assertEquals(serverUrl + ContextPaths.EIDAS_CONTEXT_PATH,
                            configHolder.getServerURLWithContextPath());
  }

}
