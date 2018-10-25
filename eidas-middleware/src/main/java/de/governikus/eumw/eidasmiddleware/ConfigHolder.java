/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
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
import java.util.Properties;

import de.governikus.eumw.eidasmiddleware.pkcs11.EidsaSignerCredentialConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import de.governikus.eumw.eidascommon.Utils;
import de.governikus.eumw.eidascommon.Utils.X509KeyPair;
import de.governikus.eumw.eidasstarterkit.EidasContactPerson;
import de.governikus.eumw.eidasstarterkit.EidasOrganisation;
import de.governikus.eumw.poseidas.cardbase.StringUtil;
import org.opensaml.security.x509.BasicX509Credential;


public class ConfigHolder
{

  private static final Log LOG = LogFactory.getLog(ConfigHolder.class);

  private static final String CONFIG_FILE_NAME = "eidasmiddleware.properties";

  private static final String KEY_SERVICE_PROVIDER_CONFIG_FOLDER_FOLDER = "SERVICE_PROVIDER_CONFIG_FOLDER";

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
  private static final String KEY_CONTACT_PERSON_COMPANY = "CONTACT_PERSON_COMPANY";

  private static final String KEY_CONTACT_PERSON_EMAIL = "CONTACT_PERSON_EMAIL";

  private static final String KEY_CONTACT_PERSON_GIVENNAME = "CONTACT_PERSON_GIVENNAME";

  private static final String KEY_CONTACT_PERSON_SURNAME = "CONTACT_PERSON_SURNAME";

  private static final String KEY_CONTACT_PERSON_TEL = "CONTACT_PERSON_TEL";

  /**
   * Eu Middleware ENTITYID to be used towards POSeIDAS
   */
  private static final String KEY_ENTITYID_INT = "ENTITYID_INT";

  /**
   * Eu Middleware ENTITYID to be used towards POSeIDAS
   */
  private static final String KEY_SERVER_URL = "SERVER_URL";

  /**
   * Country Code (of the country where the middleware is deployed).
   */
  private static final String KEY_COUNTRYCODE = "COUNTRYCODE";

  /**
   * ORGANIZATION Details for the idp metadata.xml
   */
  private static final String KEY_ORGANIZATION_NAME = "ORGANIZATION_NAME";

  private static final String KEY_ORGANIZATION_URL = "ORGANIZATION_URL";

  private static final String KEY_ORGANIZATION_LANG = "ORGANIZATION_LANG";

  private static final String KEY_ORGANIZATION_DISPLAY_NAME = "ORGANIZATION_DISPLAY_NAME";

  /**
   * Exception Messages
   */
  private static final String CAN_NOT_LOAD_SERVICE_DECRYPTION_CERT = "Can not load Service DecryptionCert";

  private static final String CAN_NOT_LOAD_SERVICE_DECRYPTION_KEY = "Can not load Service DecryptionKey";

  private static ConfigHolder holder = null;

  private Properties properties = null;

  private X509Certificate metadataSigner = null;

  private X509KeyPair signKey = null;

  private X509KeyPair cryptKey = null;

  private File configDir = null;

  private EidasContactPerson contactPerson = null;

  private String entityIdInt = null;

  private String serverURL;

  private String countryCode = null;

  private EidasOrganisation organization = null;

  private ConfigHolder()
  {
    super();
  }

  /**
   * Loads configuration.
   */
  static void loadProperties()
  {
    if (holder == null)
    {
      holder = new ConfigHolder();
    }

    if (StringUtil.notNullOrEmpty(System.getProperty("spring.config.additional-location")))
    {
      holder.configDir = new File(Utils.prepareSpringConfigLocation(System.getProperty("spring.config.additional-location")));
    }
    else if (StringUtil.notNullOrEmpty(System.getenv("SPRING_CONFIG_ADDITIONAL_LOCATION")))
    {
      holder.configDir = new File(Utils.prepareSpringConfigLocation(System.getenv("SPRING_CONFIG_ADDITIONAL_LOCATION")));
    }
    else
    {
      holder.configDir = new File(System.getProperty("user.dir"), "config");
    }

    File configFile = new File(holder.configDir, CONFIG_FILE_NAME);
    try (InputStream stream = new FileInputStream(configFile))
    {
      holder.properties = new Properties();
      holder.properties.load(stream);
    }
    catch (IOException e)
    {
      LOG.error("Can not load service properties", e);
    }

    if (holder.properties.getProperty(KEY_SERVER_URL) == null
        || holder.properties.getProperty(KEY_SERVER_URL).equals(""))
    {
      throw new BadConfigurationException("SERVER_URL is not set in the eidasmiddleware.properties");
    }
  }

  static File getProviderConfigDir()
  {
    return new File(holder.properties.getProperty(KEY_SERVICE_PROVIDER_CONFIG_FOLDER_FOLDER));
  }

  static X509Certificate getMetadataSignatureCert() throws CertificateException
  {
    if (ConfigHolder.holder.metadataSigner == null)
    {
      synchronized (LOCKOBJECT)
      {
        try (
          FileInputStream fis = new FileInputStream(ConfigHolder.holder.properties.getProperty(KEY_SERVICE_PROVIDER_METADATA_SIGNATURE_CERT)))
        {
          ConfigHolder.holder.metadataSigner = Utils.readCert(fis);
        }
        catch (IOException e)
        {
          throw new CertificateException(e);
        }
      }
    }
    return ConfigHolder.holder.metadataSigner;
  }

  public static PrivateKey getSignatureKey()
  {
    if (ConfigHolder.holder.signKey == null)
    {
      try
      {
        return getAppSignatureKeyPair().getKey();
      }
      catch (IOException | GeneralSecurityException e)
      {
        LOG.error(CAN_NOT_LOAD_SERVICE_DECRYPTION_KEY, e);
      }
    }
    return ConfigHolder.holder.signKey.getKey();
  }

  public static X509Certificate getSignatureCert()
  {
    if (ConfigHolder.holder.signKey == null)
    {
      try
      {
        return getAppSignatureKeyPair().getCert();
      }
      catch (IOException | GeneralSecurityException e)
      {
        LOG.error(CAN_NOT_LOAD_SERVICE_DECRYPTION_CERT, e);
      }
    }
    return ConfigHolder.holder.signKey.getCert();
  }

  public static X509Certificate getDecryptionCert()
  {
    if (ConfigHolder.holder.cryptKey == null)
    {
      try
      {
        return getAppDecryptionKeyPair().getCert();
      }
      catch (IOException | GeneralSecurityException e)
      {
        LOG.error(CAN_NOT_LOAD_SERVICE_DECRYPTION_CERT, e);
      }
    }
    return ConfigHolder.holder.cryptKey.getCert();
  }

  public static X509KeyPair getAppSignatureKeyPair() throws IOException, GeneralSecurityException
  {
    // Check is a HSM key is configured if so, then read key and cert form PKCS#11 configured token
    // The key should be read each time from the Credential to allow round robin selection of multiple PKCS#11 keys.
    BasicX509Credential pkcs11SignCredential = EidsaSignerCredentialConfiguration.getSamlMessageSigningCredential();
    if (pkcs11SignCredential != null){
      ConfigHolder.holder.signKey = new X509KeyPair(
              pkcs11SignCredential.getPrivateKey(),
              new X509Certificate[]{pkcs11SignCredential.getEntityCertificate()}
              );
      return ConfigHolder.holder.signKey;
    }

    //Legacy configured key on disk.
    if (ConfigHolder.holder.signKey == null)
    {
      synchronized (LOCKOBJECT)
      {
        String keystoreFileName = ConfigHolder.holder.properties.getProperty(KEY_APP_SIGN_KEY);
        try (FileInputStream fis = new FileInputStream(keystoreFileName))
        {
          ConfigHolder.holder.signKey = Utils.readKeyAndCert(fis,
                                                             keystoreFileName.toLowerCase().endsWith("jks")
                                                               ? "JKS" : "PKCS12",
                                                             ConfigHolder.holder.properties.getProperty(KEY_APP_SIGN_PIN)
                                                                                           .toCharArray(),
                                                             ConfigHolder.holder.properties.getProperty(KEY_APP_SIGN_ALIAS),
                                                             ConfigHolder.holder.properties.getProperty(KEY_APP_SIGN_PIN)
                                                                                           .toCharArray(),
                                                             true);
          return ConfigHolder.holder.signKey;
        }
      }
    }
    else
    {
      return ConfigHolder.holder.signKey;
    }
  }

  private static X509KeyPair getAppDecryptionKeyPair() throws IOException, GeneralSecurityException
  {
    // Check is a HSM key is configured if so, then read key and cert form PKCS#11 configured token
    // The key should be read each time from the Credential to allow round robin selection of multiple PKCS#11 keys.
    // The same key is selected as for signing simply because the decryption key is not used for any producation task.
    // It is only used in demos
    BasicX509Credential pkcs11SignCredential = EidsaSignerCredentialConfiguration.getSamlMessageSigningCredential();
    if (pkcs11SignCredential != null){
      ConfigHolder.holder.signKey = new X509KeyPair(
              pkcs11SignCredential.getPrivateKey(),
              new X509Certificate[]{pkcs11SignCredential.getEntityCertificate()}
      );
      return ConfigHolder.holder.signKey;
    }
    if (ConfigHolder.holder.cryptKey == null)
    {
      synchronized (LOCKOBJECT)
      {
        String keystoreFileName = ConfigHolder.holder.properties.getProperty(KEY_APP_CRYPT_KEY);
        try (FileInputStream fis = new FileInputStream(keystoreFileName))
        {
          ConfigHolder.holder.cryptKey = Utils.readKeyAndCert(fis,
                                                              keystoreFileName.toLowerCase().endsWith("jks")
                                                                ? "JKS" : "PKCS12",
                                                              ConfigHolder.holder.properties.getProperty(KEY_APP_CRYPT_PIN)
                                                                                            .toCharArray(),
                                                              ConfigHolder.holder.properties.getProperty(KEY_APP_CRYPT_ALIAS),
                                                              ConfigHolder.holder.properties.getProperty(KEY_APP_CRYPT_PIN)
                                                                                            .toCharArray(),
                                                              true);
          return ConfigHolder.holder.cryptKey;
        }
      }
    }
    else
    {
      return ConfigHolder.holder.cryptKey;
    }
  }

  public static synchronized EidasContactPerson getContactPerson()
  {
    if (ConfigHolder.holder.contactPerson == null)
    {
      ConfigHolder.holder.contactPerson = new EidasContactPerson(ConfigHolder.holder.properties.getProperty(KEY_CONTACT_PERSON_COMPANY),
                                                                 ConfigHolder.holder.properties.getProperty(KEY_CONTACT_PERSON_GIVENNAME),
                                                                 ConfigHolder.holder.properties.getProperty(KEY_CONTACT_PERSON_SURNAME),
                                                                 ConfigHolder.holder.properties.getProperty(KEY_CONTACT_PERSON_TEL),
                                                                 ConfigHolder.holder.properties.getProperty(KEY_CONTACT_PERSON_EMAIL));
    }
    return ConfigHolder.holder.contactPerson;
  }

  public static synchronized String getEntityIDInt()
  {
    if (ConfigHolder.holder.entityIdInt == null)
    {
      ConfigHolder.holder.entityIdInt = ConfigHolder.holder.properties.getProperty(KEY_ENTITYID_INT);
    }
    return ConfigHolder.holder.entityIdInt;
  }

  /**
   * Return the value for SERVER_URL with the default context path
   */
  public static synchronized String getServerURLWithContextPath()
  {
    if (ConfigHolder.holder.serverURL == null)
    {
      ConfigHolder.holder.serverURL = ConfigHolder.holder.properties.getProperty(KEY_SERVER_URL);
    }
    return ConfigHolder.holder.serverURL + EIDASMiddlewareApplication.CONTEXT_PATH;
  }

  public static synchronized String getCountryCode()
  {
    if (ConfigHolder.holder.countryCode == null)
    {
      ConfigHolder.holder.countryCode = ConfigHolder.holder.properties.getProperty(KEY_COUNTRYCODE);
    }
    return ConfigHolder.holder.countryCode;
  }

  public static synchronized EidasOrganisation getOrganization()
  {
    if (ConfigHolder.holder.organization == null)
    {
      ConfigHolder.holder.organization = new EidasOrganisation(ConfigHolder.holder.properties.getProperty(KEY_ORGANIZATION_NAME),
                                                               ConfigHolder.holder.properties.getProperty(KEY_ORGANIZATION_DISPLAY_NAME),
                                                               ConfigHolder.holder.properties.getProperty(KEY_ORGANIZATION_URL),
                                                               ConfigHolder.holder.properties.getProperty(KEY_ORGANIZATION_LANG));
    }
    return ConfigHolder.holder.organization;
  }

}
