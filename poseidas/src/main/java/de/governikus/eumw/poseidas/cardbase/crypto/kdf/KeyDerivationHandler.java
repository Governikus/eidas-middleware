/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.kdf;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;


/**
 * Interface for handlers performing key derivations.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface KeyDerivationHandler
{

  /**
   * Derive key from CAN, PIN or PUK of card.
   *
   * @param data byte-array containing CAN, PIN or PUK, <code>null</code> or empty not permitted
   * @return derived key
   * @throws IllegalArgumentException if data <code>null</code> or empty
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws InvalidKeyException
   * @throws NoSuchProviderException
   */
  public abstract SecretKey deriveCANPINPUKKey(byte[] data) throws
    InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException;

  /**
   * Derive key for encryption.
   *
   * @param data data to use for derivation, <code>null</code> or empty data not permitted
   * @param nonce nonce, <code>null</code> permitted
   * @return derived key
   * @throws IllegalArgumentException if data <code>null</code> or empty
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws InvalidKeyException
   * @throws NoSuchProviderException
   */
  public abstract SecretKey deriveEncKey(byte[] data, byte[] nonce) throws
    InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException;

  /**
   * Derive key for MAC calculations.
   *
   * @param data data to use for derivation, <code>null</code> or empty data not permitted
   * @param nonce nonce, <code>null</code> permitted
   * @return derived key
   * @throws IllegalArgumentException if data <code>null</code> or empty
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws InvalidKeyException
   * @throws NoSuchProviderException
   */
  public abstract SecretKey deriveMACKey(byte[] data, byte[] nonce) throws
    InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException;
}
