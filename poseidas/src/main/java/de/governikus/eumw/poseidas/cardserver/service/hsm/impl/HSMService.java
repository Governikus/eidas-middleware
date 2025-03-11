/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardserver.service.Service;


/**
 * Interface for operations performed using a HSM.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface HSMService extends Service
{

  /**
   * Constant for using no HSM.
   */
  public static final int NO_HSM = 1;

  /**
   * Constant for using the Utimaco eID HSM.
   */
  // public static final int UTIMACO_EID_HSM = 2;

  /**
   * Constant for using the Thales HSM.
   */
  // public static final int THALES_HSM = 3;

  /**
   * Constant for using an Utimaco eID HSM cluster.
   */
  // public static final int UTIMACO_EID_HSM_CLUSTER = 4;

  /**
   * Constant for using an HSM offering PKCS#11 interface.
   */
  public static final int PKCS11_HSM = 5;

  /**
   * Generates a new key pair with given algorithm and parameter spec. Warning: If used on a cluster where a
   * key with same alias is already existing and option replace is chosen, the machine running this MUST
   * complete the key distribution at all cost, otherwise there will be keys with same name but different
   * content on the HSM instances!
   *
   * @param algorithm algorithm to use, <code>null</code> or empty not permitted
   * @param spec parameter spec to use, <code>null</code> not permitted
   * @param alias alias for storing the new private key, WITHOUT prefix, <code>null</code> or empty not
   *          permitted
   * @param issuerAlias alias for signing the new key, WITHOUT prefix, <code>null</code> or empty permitted
   *          for self-signing
   * @param replace flag indicating if (possibly existing) key with same alias should be replaced
   * @param lifespan key validity in months
   * @return generated key pair
   * @throws IOException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   * @throws HSMException
   * @throws IllegalStateException if called when not initialized
   */
  public abstract KeyPair generateKeyPair(String algorithm,
                                          AlgorithmParameterSpec spec,
                                          String alias,
                                          String issuerAlias,
                                          boolean replace,
                                          int lifespan)
    throws IOException, NoSuchAlgorithmException, NoSuchProviderException, HSMException,
    InvalidAlgorithmParameterException, CertificateException;

  /**
   * Signs given data with requested key and algorithm.
   *
   * @param alias alias of key to use, WITHOUT prefix, <code>null</code> or empty not permitted
   * @param sigAlgOID algorithm for signing, <code>null</code> not permitted
   * @param data data to be signed, <code>null</code> or empty not permitted
   * @return signature
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws IOException
   * @throws UnrecoverableKeyException
   * @throws KeyStoreException
   * @throws CertificateException
   * @throws InvalidKeyException
   * @throws SignatureException
   * @throws InvalidKeySpecException
   * @throws HSMException
   * @throws IllegalStateException if called when not initialized
   */
  public abstract byte[] sign(String alias, OID sigAlgOID, byte[] data) throws NoSuchAlgorithmException,
    NoSuchProviderException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException,
    InvalidKeyException, SignatureException, InvalidKeySpecException, HSMException;

  /**
   * Gets associated public key for given alias of private key.
   *
   * @param alias alias of (private) key, WITHOUT prefix, <code>null</code> or empty not permitted
   * @return key, <code>null</code> if not found on any working HSM
   * @throws IllegalStateException if called when not initialized
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws HSMException
   * @throws IOException
   */
  public abstract PublicKey getPublicKey(String alias) throws HSMException, IOException;

  /**
   * Gets list of aliases of all keys (accessible for the user logged in) in HSM.
   *
   * @return aliases as {@link List}, WITHOUT prefix
   * @throws HSMException
   * @throws IOException
   * @throws IllegalStateException if called when not initialized
   */
  public abstract List<String> getAliases() throws HSMException, IOException;

  /**
   * Deletes key from HSM.
   *
   * @param alias alias of key to be deleted, WITHOUT prefix, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws HSMException
   * @throws IOException
   * @throws IllegalStateException if called when not initialized
   */
  public abstract void deleteKey(String alias) throws IOException, HSMException;

  /**
   * Checks if a key is contained in the HSM.
   *
   * @param alias alias of key, WITHOUT prefix, <code>null</code> or empty not permitted
   * @return <code>true</code> if key is found in at least one working HSM, <code>false</code> if not found on
   *         any working HSM
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws HSMException
   * @throws IOException
   * @throws IllegalStateException if called when not initialized
   */
  public abstract boolean containsKey(String alias) throws IOException, HSMException;

  /**
   * Initializes HSM and performs login. Must be called before using any other method.
   *
   * @param config configuration data, <code>null</code> not permitted, must be instance of class matching
   *          specific HSM implementation (ex: {@link PKCS11HSMConfiguration} for {@link PKCS11HSMService})
   * @throws IllegalArgumentException if config <code>null</code> or of wrong type
   * @throws HSMException if login fails
   */
  public abstract void init(HSMConfiguration config) throws HSMException;

  /**
   * Performs logout. If called, requires another call to {@link #init()} before HSM can be used again.
   *
   * @throws HSMException
   * @throws IOException
   * @throws IllegalStateException if called when not initialized
   */
  public abstract void logout() throws HSMException, IOException;

  /**
   * Checks if HSM is alive.
   *
   * @param allInstances <code>true</code> if all HSM instances in a cluster must be alive to yield the result
   *          "available", <code>false</code> if one single HSM is sufficient, ignored if no cluster is used
   * @return <code>true</code> if alive, <code>false</code> if not
   * @throws HSMException
   * @throws IOException
   */
  public abstract boolean isAlive(boolean allInstances) throws HSMException, IOException;

  /**
   * Checks if HSM service is initialized.
   *
   * @return <code>true</code> if initialized, <code>false</code> if not
   */
  public abstract boolean isInitialized();

  /**
   * Gets date of key generation.
   *
   * @param alias alias of key, WITHOUT prefix, <code>null</code> or empty not permitted
   * @return date of key generation, <code>null</code> if key not found on any working HSM
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws IllegalStateException if called when not initialized
   * @throws HSMException
   * @throws IOException
   */
  public abstract Date getGenerationDate(String alias) throws HSMException, IOException;

  /**
   * Gets date of key expiration.
   *
   * @param alias alias of key, WITHOUT prefix, <code>null</code> or empty not permitted
   * @return date of key expiration, <code>null</code> if key not found on any working HSM
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws IllegalStateException if called when not initialized
   * @throws HSMException
   * @throws IOException
   */
  public abstract Date getExpirationDate(String alias) throws HSMException, IOException;

  /**
   * Gets information whether key with given name is currently being modified (important for HSM clusters as
   * data distribution over all HSM instances may take some time). For single HSMs, this always returns
   * <code>false</code>.
   *
   * @param alias alias of key, WITHOUT prefix, <code>null</code> or empty not permitted
   * @return <code>true</code> if key undergoing modifications, <code>false</code> if not or if no HSM cluster
   *         used
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws IllegalStateException if called when not initialized
   */
  public abstract boolean isKeyBeingModified(String alias);

  /**
   * Distributes a key to all HSM instances by trying to find the key on one instance and spreading it to the
   * others.
   *
   * @param alias alias of key to be distributed, WITHOUT prefix, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws IllegalStateException if called when not initialized
   * @throws IOException
   * @throws HSMException
   */
  public abstract void distributeKey(String alias) throws IOException, HSMException;

  /**
   * Exports a private key from HSM.
   *
   * @param alias alias of key to be distributed, WITHOUT prefix, <code>null</code> or empty not permitted
   * @return byte-array containing key (typically in encrypted state)
   * @throws IllegalArgumentException if alias <code>null</code> or empty
   * @throws IllegalStateException if called when not initialized or not configured for export
   * @throws IOException
   * @throws HSMException
   */
  public abstract byte[] exportKey(String alias) throws IOException, HSMException;

  /**
   * Gets the HSM based keystore if possible.
   *
   * @return keystore, <code>null</code> if not available
   */
  public abstract KeyStore getKeyStore();
}
