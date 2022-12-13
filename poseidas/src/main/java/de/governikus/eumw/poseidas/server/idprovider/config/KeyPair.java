/*
 * Copyright (c) 2021 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;


/**
 * This class is a wrapper class for an entry of a {@link KeyStore}. It contains the key store, the alias and the
 * password for the entry so that the {@link PrivateKey} and {@link java.security.cert.Certificate} can be directly
 * accessed.
 */
public class KeyPair
{

  private final KeyStore keyStore;

  private final String alias;

  private final String password;

  /**
   * Create the wrapper for an entry of a {@link KeyStore}.
   *
   * @param keyStore The already initialized key store
   * @param alias The alias for the key store entry
   * @param keyPassword The password for the entry
   */
  public KeyPair(KeyStore keyStore, String alias, String keyPassword)
  {
    this.keyStore = keyStore;
    this.password = keyPassword;

    try
    {
      // Check if the alias is valid
      if (!keyStore.containsAlias(alias))
      {
        throw new ConfigurationException("Keystore does not contain an entry with alias : " + alias);
      }
      this.alias = alias;

      // Check if the keyPassword is valid
      keyStore.getKey(alias, keyPassword == null ? new char[0] : keyPassword.toCharArray());
    }
    catch (Exception e)
    {
      throw new ConfigurationException("Cannot access the entry of the key store", e);
    }
  }

  /**
   * Get the {@link X509Certificate} of this key pair
   */
  public X509Certificate getCertificate()
  {
    try
    {
      return (X509Certificate)keyStore.getCertificate(alias);
    }
    catch (KeyStoreException e)
    {
      throw new ConfigurationException("Cannot get certificate for alias " + alias, e);
    }
  }

  /**
   * Get the {@link PrivateKey} of this key pair
   */
  public PrivateKey getKey()
  {
    try
    {
      return (PrivateKey)keyStore.getKey(alias, password == null ? new char[0] : password.toCharArray());
    }
    catch (Exception e)
    {
      throw new ConfigurationException("Cannot get key for alias " + alias, e);
    }
  }
}
