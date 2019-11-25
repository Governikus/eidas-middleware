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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Properties;

import org.springframework.stereotype.Component;

import de.governikus.eumw.eidascommon.ContextPaths;
import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.EidasContactPerson;
import de.governikus.eumw.eidasstarterkit.EidasOrganisation;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import lombok.extern.slf4j.Slf4j;


/**
 * Load the properties for the middleware and the respective key stores and certificates
 */
@Component
@Slf4j
public class ConfigHolder
{

  private static final String CONFIG_FILE_NAME = "eidasmiddleware.properties";

  private static final String KEY_SERVICE_PROVIDER_CONFIG_FOLDER = "SERVICE_PROVIDER_CONFIG_FOLDER";

  private static final String KEY_SERVICE_PROVIDER_METADATA_SIGNATURE_CERT = "SERVICE_PROVIDER_METADATA_SIGNATURE_CERT";

  private static final Object LOCKOBJECT = new Object();

  /**
   * Path to the signature keystore for the SAML interface
   */
  private static final String KEY_APP_SIGN_KEY = "MIDDLEWARE_SIGN_KEY";

  /**
   * Pin of the signature key for the SAML interface
   */
  private static final String KEY_APP_SIGN_PIN = "MIDDLEWARE_SIGN_PIN";

  /**
   * Alias of the signature key for the SAML interface
   */
  private static final String KEY_APP_SIGN_ALIAS = "MIDDLEWARE_SIGN_ALIAS";

  /**
   * Path to the decryption keystore for the SAML interface
   */
  private static final String KEY_APP_CRYPT_KEY = "MIDDLEWARE_CRYPT_KEY";

  /**
   * Pin of the decryption key for the SAML interface
   */
  private static final String KEY_APP_CRYPT_PIN = "MIDDLEWARE_CRYPT_PIN";

  /**
   * Alias of the decryption key for the SAML interface
   */
  private static final String KEY_APP_CRYPT_ALIAS = "MIDDLEWARE_CRYPT_ALIAS";

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

  /**
   * Exception Messages
   */
  private static final String CAN_NOT_LOAD_SERVICE_DECRYPTION_CERT = "Can not load Service DecryptionCert";

  private static final String CAN_NOT_LOAD_SERVICE_DECRYPTION_KEY = "Can not load Service DecryptionKey";

  private Properties properties = null;

  private X509Certificate metadataSigner = null;

  private X509KeyPair signKey = null;

  private X509KeyPair cryptKey = null;

  private EidasContactPerson contactPerson = null;

  private String entityIdInt = null;

  private String serverURL;

  private String countryCode = null;

  private EidasOrganisation organization = null;

  private String metadataValidity;

  public ConfigHolder()
  {
    loadProperties();
  }

  /**
   * Additional constructor for testing purposes
   *
   * @param properties The properties to be read
   */
  public ConfigHolder(Properties properties)
  {
    this.properties = properties;
  }

  /**
   * Loads configuration.
   */
  private void loadProperties()
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

    File configFile = new File(configDir, CONFIG_FILE_NAME);
    try (InputStream stream = new FileInputStream(configFile))
    {
      properties = new Properties();
      properties.load(stream);
    }
    catch (IOException e)
    {
      log.error("Can not load service properties", e);
    }

    if (properties.getProperty(KEY_SERVER_URL) == null || properties.getProperty(KEY_SERVER_URL).equals(""))
    {
      throw new BadConfigurationException("SERVER_URL is not set in the eidasmiddleware.properties");
    }
  }

  File getProviderConfigDir()
  {
    return new File(properties.getProperty(KEY_SERVICE_PROVIDER_CONFIG_FOLDER));
  }

  /**
   * Get the certificate to verify the signature of the connectors metadata files
   */
  X509Certificate getMetadataSignatureCert() throws CertificateException
  {
    if (metadataSigner == null)
    {
      synchronized (LOCKOBJECT)
      {
        try (
          FileInputStream fis = new FileInputStream(properties.getProperty(KEY_SERVICE_PROVIDER_METADATA_SIGNATURE_CERT)))
        {
          metadataSigner = Utils.readCert(fis);
        }
        catch (IOException e)
        {
          throw new CertificateException(e);
        }
      }
    }
    return metadataSigner;
  }

  /**
   * Get the key that is used to sign the metadata and responses
   */
  public PrivateKey getSignatureKey()
  {
    if (signKey == null)
    {
      try
      {
        return getAppSignatureKeyPair().getKey();
      }
      catch (IOException | GeneralSecurityException e)
      {
        log.error(CAN_NOT_LOAD_SERVICE_DECRYPTION_KEY, e);
      }
    }
    return signKey.getKey();
  }

  /**
   * Get the certificate than ca be used to verify the signature of the middleware's metadata and auth
   * responses
   */
  public X509Certificate getSignatureCert()
  {
    if (signKey == null)
    {
      try
      {
        return getAppSignatureKeyPair().getCert();
      }
      catch (IOException | GeneralSecurityException e)
      {
        log.error(CAN_NOT_LOAD_SERVICE_DECRYPTION_CERT, e);
      }
    }
    return signKey.getCert();
  }

  /**
   * Get the certificate that should be used by connectors to encrypt the auth requests
   */
  public X509Certificate getDecryptionCert()
  {
    if (cryptKey == null)
    {
      try
      {
        return getAppDecryptionKeyPair().getCert();
      }
      catch (IOException | GeneralSecurityException e)
      {
        log.error(CAN_NOT_LOAD_SERVICE_DECRYPTION_CERT, e);
      }
    }
    return cryptKey.getCert();
  }

  /**
   * Get the keypair to sign the messages and metadata
   */
  public X509KeyPair getAppSignatureKeyPair() throws IOException, GeneralSecurityException
  {
    if (signKey == null)
    {
      synchronized (LOCKOBJECT)
      {
        String keystoreFileName = properties.getProperty(KEY_APP_SIGN_KEY);
        try (FileInputStream fis = new FileInputStream(keystoreFileName))
        {
          signKey = Utils.readKeyAndCert(fis,
                                         keystoreFileName.toLowerCase(Locale.GERMAN).endsWith("jks") ? "JKS"
                                           : "PKCS12",
                                         properties.getProperty(KEY_APP_SIGN_PIN).toCharArray(),
                                         properties.getProperty(KEY_APP_SIGN_ALIAS),
                                         properties.getProperty(KEY_APP_SIGN_PIN).toCharArray(),
                                         true);
          return signKey;
        }
      }
    }
    else
    {
      return signKey;
    }
  }

  private X509KeyPair getAppDecryptionKeyPair() throws IOException, GeneralSecurityException
  {
    if (cryptKey == null)
    {
      synchronized (LOCKOBJECT)
      {
        String keystoreFileName = properties.getProperty(KEY_APP_CRYPT_KEY);
        try (FileInputStream fis = new FileInputStream(keystoreFileName))
        {
          cryptKey = Utils.readKeyAndCert(fis,
                                          keystoreFileName.toLowerCase(Locale.GERMAN).endsWith("jks") ? "JKS"
                                            : "PKCS12",
                                          properties.getProperty(KEY_APP_CRYPT_PIN).toCharArray(),
                                          properties.getProperty(KEY_APP_CRYPT_ALIAS),
                                          properties.getProperty(KEY_APP_CRYPT_PIN).toCharArray(),
                                          true);
          return cryptKey;
        }
      }
    }
    else
    {
      return cryptKey;
    }
  }

  public synchronized EidasContactPerson getContactPerson()
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

  public synchronized String getEntityIDInt()
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
  public synchronized String getServerURLWithContextPath()
  {
    if (serverURL == null)
    {
      serverURL = properties.getProperty(KEY_SERVER_URL);
    }
    if (serverURL.endsWith("/"))
    {
      serverURL = serverURL.substring(0, serverURL.length() - 1);
    }
    return serverURL + ContextPaths.EIDAS_CONTEXT_PATH;
  }

  public synchronized String getCountryCode()
  {
    if (countryCode == null)
    {
      countryCode = properties.getProperty(KEY_COUNTRYCODE);
    }
    return countryCode;
  }

  public synchronized EidasOrganisation getOrganization()
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

  public synchronized String getMetadataValidity()
  {
    if (metadataValidity == null)
    {
      metadataValidity = properties.getProperty(KEY_METADATA_VALIDITY);
    }
    return metadataValidity;
  }
}
