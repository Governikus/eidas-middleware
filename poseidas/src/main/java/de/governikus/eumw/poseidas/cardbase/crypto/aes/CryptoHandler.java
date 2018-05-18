/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.aes;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


/**
 * Interface for handler classes performing cryptographic operations.
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public interface CryptoHandler
{

  /**
   * Constant for the expected length of a MAC.
   */
  static final int DEFAULT_MAC_BYTE_LENGTH = 8;

  /**
   * Decrypt the nonce received from card.
   * 
   * @param key key for decryption, <code>null</code> not permitted
   * @param data encrypted nonce, <code>null</code> or empty data not permitted, length must match block size
   *          of employed cipher
   * @return decrypted nonce
   * @throws IllegalArgumentException if any argument <code>null</code> or data empty
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public abstract byte[] decryptNonce(SecretKey key, byte[] data) throws
    NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
    BadPaddingException;

  /**
   * Calculate MAC (using given key).
   * 
   * @param key key for MAC calculation, <code>null</code> not permitted
   * @param data data to be MACed, <code>null</code> not permitted
   * @return MAC
   * @throws IllegalArgumentException if any argument <code>null</code>
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws NoSuchPaddingException
   */
  public abstract byte[] mac(SecretKey key, byte[] data) throws InvalidKeyException,
    NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException,
    BadPaddingException;
}
