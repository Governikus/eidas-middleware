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

import java.util.Arrays;
import java.util.List;



/**
 * Factory for {@link KeyHandler}.
 *
 * @author Jens Wothe, jw@bos-bremen.de
 */
public final class KeyHandlerFactory
{

  /**
   * Constructor.
   */
  private KeyHandlerFactory()
  {
    super();
  }

  // list of supported algorithms
  private static final List<String> LIST_SUPPORTED_ALGORITHMS = Arrays.asList("EC");

  /**
   * Creates a new {@link KeyHandler}.
   *
   * @param algorithm algorithm
   * @param parameter parameter, might be <code>null</code> according to {@link KeyHandler} implementation
   * @return instance of {@link KeyHandler}
   * @throws IllegalArgumentException if algorithm or parameter not valid
   */
  public static KeyHandler newKeyHandler(String algorithm, Object parameter)
  {
    if (!LIST_SUPPORTED_ALGORITHMS.contains(algorithm))
    {
      throw new IllegalArgumentException("not supported algorithm '" + algorithm + "', supported: "
                                         + LIST_SUPPORTED_ALGORITHMS.toString());
    }
    if (!Integer.class.isInstance(parameter))
    {
      throw new IllegalArgumentException("parameter for KeyHandlerEC expected to be Integer or int");
    }
    return new KeyHandlerEC(Integer.class.cast(parameter).intValue());
  }
}
