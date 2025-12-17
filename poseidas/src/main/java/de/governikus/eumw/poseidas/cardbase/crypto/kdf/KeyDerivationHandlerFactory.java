/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardbase.crypto.kdf;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;


/**
 * Factory for {@link KeyDerivationHandler}.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class KeyDerivationHandlerFactory
{

  // list of supported algorithms
  private static final List<String> LIST_SUPPORTED_ALGORITHMS = Arrays.asList("AES");

  /**
   * Constructor.
   */
  private KeyDerivationHandlerFactory()
  {
    super();
  }

  /**
   * Creates new {@link KeyDerivationHandler}.
   *
   * @param algorithm algorithm
   * @param keyLength key length, implementation checks requirements of key length
   * @return instance of {@link KeyDerivationHandler}
   * @throws IllegalArgumentException if algorithm keyLength not one accepted values
   * @throws NoSuchAlgorithmException
   */
  public static KeyDerivationHandler newKeyDerivationHandler(String algorithm, int keyLength)
    throws NoSuchAlgorithmException
  {
    if (!LIST_SUPPORTED_ALGORITHMS.contains(algorithm))
    {
      throw new IllegalArgumentException("not supported algorithm '" + algorithm + "', supported: "
                                         + LIST_SUPPORTED_ALGORITHMS.toString());
    }
    return new KeyDerivationAES(keyLength);
  }

}
