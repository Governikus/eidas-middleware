/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.configuration.migration.models.eidas;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Properties;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.EidasContactPerson;
import de.governikus.eumw.eidasstarterkit.EidasOrganisation;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Load the properties for the middleware and the respective key stores and certificates
 */
@Slf4j
@NoArgsConstructor
public class ConfigHolder
{

  /**
   * Pin of the signature key for the SAML interface
   */
  public static final String KEY_APP_SIGN_PIN = "MIDDLEWARE_SIGN_PIN";

  /**
   * Alias of the signature key for the SAML interface
   */
  public static final String KEY_APP_SIGN_ALIAS = "MIDDLEWARE_SIGN_ALIAS";

  /**
   * Pin of the decryption key for the SAML interface
   */
  public static final String KEY_APP_CRYPT_PIN = "MIDDLEWARE_CRYPT_PIN";

  /**
   * Alias of the decryption key for the SAML interface
   */
  public static final String KEY_APP_CRYPT_ALIAS = "MIDDLEWARE_CRYPT_ALIAS";

  /**
   * Contact Person Details for the idp metadata.xml
   */
  static final String KEY_CONTACT_PERSON_COMPANY = "CONTACT_PERSON_COMPANY";

  static final String KEY_CONTACT_PERSON_EMAIL = "CONTACT_PERSON_EMAIL";

  static final String KEY_CONTACT_PERSON_GIVENNAME = "CONTACT_PERSON_GIVENNAME";

  static final String KEY_CONTACT_PERSON_SURNAME = "CONTACT_PERSON_SURNAME";

  static final String KEY_CONTACT_PERSON_TEL = "CONTACT_PERSON_TEL";

  /**
   * Validity of idp metadata
   */
  static final String KEY_METADATA_VALIDITY = "METADATA_VALIDITY";

  /**
   * Eu Middleware ENTITYID to be used towards POSeIDAS
   */
  static final String KEY_ENTITYID_INT = "ENTITYID_INT";

  /**
   * Eu Middleware ENTITYID to be used towards POSeIDAS
   */
  static final String KEY_SERVER_URL = "SERVER_URL";

  /**
   * Country Code (of the country where the middleware is deployed).
   */
  static final String KEY_COUNTRYCODE = "COUNTRYCODE";

  /**
   * ORGANIZATION Details for the idp metadata.xml
   */
  static final String KEY_ORGANIZATION_NAME = "ORGANIZATION_NAME";

  static final String KEY_ORGANIZATION_URL = "ORGANIZATION_URL";

  static final String KEY_ORGANIZATION_LANG = "ORGANIZATION_LANG";

  static final String KEY_ORGANIZATION_DISPLAY_NAME = "ORGANIZATION_DISPLAY_NAME";

  private static final String CONFIG_FILE_NAME = "eidasmiddleware.properties";

  private static final String KEY_SERVICE_PROVIDER_CONFIG_FOLDER = "SERVICE_PROVIDER_CONFIG_FOLDER";

  private static final String KEY_SERVICE_PROVIDER_METADATA_SIGNATURE_CERT = "SERVICE_PROVIDER_METADATA_SIGNATURE_CERT";

  /**
   * Flag indicating if the application shall sign its metadata.
   */
  private static final String KEY_APP_DO_SIGN_METADATA = "MIDDLEWARE_DO_SIGN_METADATA";

  /**
   * Path to the signature keystore for the SAML interface
   */
  private static final String KEY_APP_SIGN_KEY = "MIDDLEWARE_SIGN_KEY";

  /**
   * Path to the decryption keystore for the SAML interface
   */
  private static final String KEY_APP_CRYPT_KEY = "MIDDLEWARE_CRYPT_KEY";

  @Getter
  private Properties properties;

  private X509Certificate metadataSigner;

  private X509KeyPair signKey;

  private X509KeyPair cryptKey;

  private EidasContactPerson contactPerson;

  private String entityIdInt;

  private String serverURL;

  private String countryCode;

  private EidasOrganisation organization;

  private String pathToConfigFolder;

  /**
   * When setting the path to config folder for migration make is canonical.
   * 
   * @param inputPathToConfig
   * @throws IOException
   */
  public void setCanonicalPathToConfigFolder(String inputPathToConfig) throws IOException
  {
    File file = new File(inputPathToConfig);
    if (file.isAbsolute())
    {
      pathToConfigFolder = file.getCanonicalPath();
    }
    else
    {
      pathToConfigFolder = new File(new File(System.getProperty("user.dir")), inputPathToConfig).getCanonicalPath();
    }
  }

  /**
   * Loads configuration.
   */
  public void loadProperties(String configDirPath) throws IOException
  {

    File configDir;
    setCanonicalPathToConfigFolder(configDirPath);
    log.info("Load old config from path {}", pathToConfigFolder);
    configDir = new File(pathToConfigFolder);
    File configFile = new File(configDir, CONFIG_FILE_NAME);
    try (InputStream stream = new FileInputStream(configFile))
    {
      properties = new Properties();
      properties.load(stream);
    }
  }

  /**
   * Get the folder where the service provider metadata files are stored
   *
   * @return directory with the metadata files
   */
  public File getProviderConfigDir() throws IOException
  {
    return new File(getCanonicalPath(properties.getProperty(KEY_SERVICE_PROVIDER_CONFIG_FOLDER)));
  }

  /**
   * Get the certificate to verify the signature of the connectors metadata files
   */
  public X509Certificate getMetadataSignatureCert() throws CertificateException
  {
    if (metadataSigner == null)
    {
      try (
        FileInputStream fis = new FileInputStream(getCanonicalPath(properties.getProperty(KEY_SERVICE_PROVIDER_METADATA_SIGNATURE_CERT))))
      {
        metadataSigner = Utils.readCert(fis);
      }
      catch (IOException e)
      {
        throw new CertificateException(e);
      }
    }
    return metadataSigner;
  }

  /**
   * Get the keypair to sign the messages and metadata
   */
  public X509KeyPair getAppSignatureKeyPair() throws IOException, GeneralSecurityException
  {
    if (signKey == null)
    {
      String keystoreFileName = getCanonicalPath(properties.getProperty(KEY_APP_SIGN_KEY));
      if (keystoreFileName != null)
      {
        try (FileInputStream fis = new FileInputStream(keystoreFileName))
        {
          signKey = Utils.readKeyAndCert(fis,
                                         getAppSignatureKeyStoreType(),
                                         properties.getProperty(KEY_APP_SIGN_PIN).toCharArray(),
                                         properties.getProperty(KEY_APP_SIGN_ALIAS),
                                         properties.getProperty(KEY_APP_SIGN_PIN).toCharArray(),
                                         true);
          return signKey;
        }
      }
    }
    return signKey;
  }

  /**
   * Get the type of the signature key store
   *
   * @return the type of the keystore
   */
  public String getAppSignatureKeyStoreType()
  {
    String keyStoreFileName = properties.getProperty(KEY_APP_SIGN_KEY);
    return keyStoreFileName.toLowerCase(Locale.GERMAN).endsWith("jks") ? "JKS" : "PKCS12";
  }

  /**
   * Get the type of the encryption key store
   *
   * @return the type of the keystore
   */
  public String getAppCryptionKeyStoreType()
  {
    String keyStoreFileName = properties.getProperty(KEY_APP_CRYPT_KEY);
    return keyStoreFileName.toLowerCase(Locale.GERMAN).endsWith("jks") ? "JKS" : "PKCS12";
  }

  /**
   * Get the depryption key pair
   *
   * @return the decryption key pair
   * @throws IOException when the key pair cannot be read
   * @throws GeneralSecurityException when the key pair cannot be loaded
   */
  public X509KeyPair getAppDecryptionKeyPair() throws IOException, GeneralSecurityException
  {
    if (cryptKey == null)
    {
      String keystoreFileName = getCanonicalPath(properties.getProperty(KEY_APP_CRYPT_KEY));
      try (FileInputStream fis = new FileInputStream(keystoreFileName))
      {
        cryptKey = Utils.readKeyAndCert(fis,
                                        getAppCryptionKeyStoreType(),
                                        properties.getProperty(KEY_APP_CRYPT_PIN).toCharArray(),
                                        properties.getProperty(KEY_APP_CRYPT_ALIAS),
                                        properties.getProperty(KEY_APP_CRYPT_PIN).toCharArray(),
                                        true);
        return cryptKey;
      }
    }
    else
    {
      return cryptKey;
    }
  }

  /**
   * Get the contact person from the eidasmiddleware.properties
   *
   * @return the {@link EidasContactPerson} with all information
   */
  public EidasContactPerson getContactPerson()
  {
    if (contactPerson == null)
    {
      contactPerson = new EidasContactPerson(properties.getProperty(KEY_CONTACT_PERSON_COMPANY),
                                             properties.getProperty(KEY_CONTACT_PERSON_GIVENNAME),
                                             properties.getProperty(KEY_CONTACT_PERSON_SURNAME),
                                             properties.getProperty(KEY_CONTACT_PERSON_TEL),
                                             properties.getProperty(KEY_CONTACT_PERSON_EMAIL));
    }
    return contactPerson;
  }

  /**
   * Get the entity ID of the public service provider
   *
   * @return the entity ID of the public service provider
   */
  public String getEntityIDInt()
  {
    if (entityIdInt == null)
    {
      entityIdInt = properties.getProperty(KEY_ENTITYID_INT);
    }
    return entityIdInt;
  }

  /**
   * Return the value for SERVER_URL with the default context path
   */
  public String getServerUrl()
  {
    if (serverURL == null)
    {
      serverURL = properties.getProperty(KEY_SERVER_URL);
    }
    if (serverURL.endsWith("/"))
    {
      serverURL = serverURL.substring(0, serverURL.length() - 1);
    }
    return serverURL;
  }

  /**
   * Get the country code from the eidasmiddleware.properties
   *
   * @return the country code for this eidas middleware
   */
  public String getCountryCode()
  {
    if (countryCode == null)
    {
      countryCode = properties.getProperty(KEY_COUNTRYCODE);
    }
    return countryCode;
  }

  /**
   * Get the organization from the eidasmiddleware.properties
   *
   * @return the {@link EidasOrganisation} with all information
   */
  public EidasOrganisation getOrganization()
  {
    if (organization == null)
    {
      organization = new EidasOrganisation(properties.getProperty(KEY_ORGANIZATION_NAME),
                                           properties.getProperty(KEY_ORGANIZATION_DISPLAY_NAME),
                                           properties.getProperty(KEY_ORGANIZATION_URL),
                                           properties.getProperty(KEY_ORGANIZATION_LANG));
    }
    return organization;
  }

  /**
   * Get the information if the metadata of the eidas middleware should be signed
   *
   * @return true if the metadata of the eidas middleware should be signed, otherwise false
   */
  public boolean isDoSignMetadata()
  {
    return Boolean.parseBoolean(properties.getProperty(KEY_APP_DO_SIGN_METADATA, "true"));
  }

  private String getCanonicalPath(String path) throws IOException
  {
    File file = new File(path);
    if (file.isAbsolute())
    {
      return file.getCanonicalPath();
    }
    String newCanonicalPath = new File(new File(pathToConfigFolder).getParent(), path).getCanonicalPath();
    log.info("Changed relative path: {} to canonical path: {}", path, newCanonicalPath);
    return newCanonicalPath;
  }
}
