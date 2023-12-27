/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.key;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import de.governikus.eumw.poseidas.cardbase.asn1.OID;
import de.governikus.eumw.poseidas.cardbase.asn1.npa.si.DomainParameterInfo;


/**
 * Interface for key operation handlers.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface KeyHandler
{

  /**
   * Generates a key pair.
   *
   * @param params {@link DomainParameterInfo} to use in generation, <code>null</code> not permitted
   * @return generated {@link KeyPair}
   * @throws IllegalArgumentException if params <code>null</code>
   * @throws IOException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   */
  public abstract KeyPair generateKeyPair(DomainParameterInfo params) throws
    IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;

  /**
   * Generates a key pair.
   *
   * @param spec {@link AlgorithmParameterSpec} to use in generation, <code>null</code> not permitted
   * @return generated {@link KeyPair}
   * @throws IllegalArgumentException if spec <code>null</code> or of wrong type
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws InvalidAlgorithmParameterException
   */
  public abstract KeyPair generateKeyPair(AlgorithmParameterSpec spec) throws
    NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;

  /**
   * Builds {@link PublicKey} object from byte-array encoding the key.
   *
   * @param params domain parameters as {@link DomainParameterInfo}, <code>null</code> not permitted
   * @param keyBytes key data as byte-array, <code>null</code> or empty not permitted
   * @return generated {@link PublicKey}
   * @throws IllegalArgumentException if any argument <code>null</code> or if keyBytes empty
   * @throws IOException
   * @throws InvalidKeySpecException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   */
  public abstract PublicKey buildKeyFromBytes(DomainParameterInfo params, byte[] keyBytes)
    throws IOException;

  /**
   * Builds {@link PublicKey} object from byte-array encoding the key.
   *
   * @param spec domain parameters as {@link AlgorithmParameterSpec}, <code>null</code> not permitted
   * @param keyBytes key data as byte-array, <code>null</code> or empty not permitted
   * @return generated {@link PublicKey}
   * @throws IllegalArgumentException if any argument <code>null</code>, keyBytes empty or spec of wrong type
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   */
  public abstract PublicKey buildKeyFromBytes(AlgorithmParameterSpec spec, byte[] keyBytes);

  /**
   * Calculates shared secret and delivers result in format required for next step.
   *
   * @param priv own {@link PrivateKey}, <code>null</code> not permitted
   * @param pub received {@link PublicKey}, <code>null</code> not permitted
   * @return shared secret as byte-array
   * @throws IllegalArgumentException if any argument <code>null</code> or of wrong type
   */
  public abstract byte[] calculateSharedSecret(PrivateKey priv, PublicKey pub);

  /**
   * Converts {@link PublicKey} key to bytes.
   *
   * @param key {@link PublicKey} to be converted, <code>null</code> not permitted
   * @return key as byte-array
   * @throws IllegalArgumentException if given key <code>null</code> or of wrong type
   */
  public abstract byte[] ephemeralKeyBytes(PublicKey key);

  /**
   * Generate the structure to be used for calculating authentication token. Structure is defined in BSI
   * TR-03110.
   *
   * @param key the key to be converted, <code>null</code> not permitted
   * @param oid {@link OID} to use in structure, <code>null</code> not permitted
   * @param fullStructure flag indicating if the structure shall contain optional data or not
   * @return byte array of the ASN.1 structure containing the public key, <code>null</code> if converting
   *         fails
   * @throws IllegalArgumentException if key or oid <code>null</code> or key of wrong type
   * @throws IOException
   */
  public abstract byte[] convertPublicKey(PublicKey key, OID oid, boolean fullStructure)
    throws IOException;

  /**
   * Compresses a public key.
   *
   * @param key key to be compressed, <code>null</code> not permitted
   * @return compressed key as byte-array
   * @throws IllegalArgumentException if given key <code>null</code>
   */
  public abstract byte[] compressKey(PublicKey key);

  /**
   * Compresses a public key given as byte-array.
   *
   * @param key key to be compressed, <code>null</code> or empty not permitted
   * @return compressed key as byte-array
   * @throws IllegalArgumentException if given key <code>null</code> or empty
   */
  public abstract byte[] compressKey(byte[] key);

  /**
   * Generates byte-array representation of key related object (exact type depending on implementation).
   *
   * @param o object to be encoded, <code>null</code> not permitted
   * @return byte-array containing object representation
   * @throws IllegalArgumentException if o <code>null</code> or of wrong type
   */
  public abstract byte[] getEncoded(Object o);
}
