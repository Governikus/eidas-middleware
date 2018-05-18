/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardbase.crypto.aes.CryptoHandler;


/**
 * Factory for {@link CryptoHandler}.
 * 
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class CMACFactory
{

  // list of supported algorithms
  private static final List<String> LIST_SUPPORTED_ALGORITHMS = Arrays.asList("AES");

  /**
   * Constructor.
   */
  private CMACFactory()
  {
    super();
  }

  /**
   * Creates new {@link CMAC}.
   * 
   * @param key key, <code>null</code> not permitted
   * @param algorithm algorithm, <code>null</code> or empty String not permitted
   * @return instance CMAC
   * @throws InvalidKeyException if key invalid
   * @throws IllegalArgumentException if key or algorithm not accepted
   * @throws NoSuchAlgorithmException if algorithm not found
   * @throws NoSuchPaddingException if padding not found
   */
  public static CMAC newMAC(SecretKey key, String algorithm) throws InvalidKeyException,
    NoSuchPaddingException, NoSuchAlgorithmException
  {
    AssertUtil.notNull(key, "key");
    AssertUtil.notNullOrEmpty(algorithm, "algorithm");
    if (!LIST_SUPPORTED_ALGORITHMS.contains(key.getAlgorithm()))
    {
      throw new IllegalArgumentException("not supported key algorithm '" + key.getAlgorithm()
                                         + "', supported: " + LIST_SUPPORTED_ALGORITHMS.toString());
    }
    if (!algorithm.startsWith(key.getAlgorithm()))
    {
      throw new IllegalArgumentException("key and algorithm inconsistent, key algorithm: "
                                         + key.getAlgorithm() + ", algorithm: " + algorithm);
    }
    if (CMACAESImpl.ALGORITHM.equals(algorithm))
    {
      return new CMACAESImpl(key, algorithm);
    }
    return null;
  }

}
