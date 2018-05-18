/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.eac.crypto.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import de.governikus.eumw.poseidas.cardbase.crypto.aes.CryptoHandler;


/**
 * AES implementation of {@link CryptoHandler} (Bouncy Castle version).
 * 
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class CryptoAES implements CryptoHandler
{

  /**
   * Reference to cipher in ECB mode.
   */
  private Cipher ecbCipher = null;

  /**
   * Constructor.
   * 
   * @param keyLength key length
   * @throws IllegalArgumentException if keyLength not one of {128, 192, 256}.
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  public CryptoAES(int keyLength) throws NoSuchAlgorithmException, NoSuchPaddingException
  {
    super();
    if (keyLength != 128 && keyLength != 192 && keyLength != 256)
    {
      throw new IllegalArgumentException("keyLength must be one of {128, 192, 256}");
    }
    this.ecbCipher = Cipher.getInstance("AES/ECB/NoPadding");
  }

  /** {@inheritDoc} */
  @Override
  public byte[] decryptNonce(SecretKey key, byte[] data) throws
    NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
    BadPaddingException
  {
    if (key == null || data == null)
    {
      throw new IllegalArgumentException("null key or data not permitted");
    }
    if (data.length != this.ecbCipher.getBlockSize())
    {
      throw new IllegalArgumentException("data length not matching block length of cipher");
    }
    this.ecbCipher.init(Cipher.DECRYPT_MODE, key);
    return this.ecbCipher.doFinal(data);
  }

  /** {@inheritDoc} */
  @Override
  public byte[] mac(SecretKey key, byte[] data)
  {
    if (key == null || data == null)
    {
      throw new IllegalArgumentException("null not permitted");
    }
    BlockCipher bc = new AESFastEngine();
    Mac m = new CMac(bc, DEFAULT_MAC_BYTE_LENGTH * 8);
    m.init(new KeyParameter(key.getEncoded()));
    byte[] result = new byte[DEFAULT_MAC_BYTE_LENGTH];
    m.update(data, 0, data.length);
    m.doFinal(result, 0);
    return result;
  }
}
