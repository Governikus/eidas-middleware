/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.cardserver.service.hsm.impl;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;
import de.governikus.eumw.poseidas.cardserver.eac.ta.CertAndKeyProvider;


/**
 * Implementation of {@link CertAndKeyProvider} used for forwarding a key to the signature handler in case no
 * HSM is used.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
public class LocalCertAndKeyProvider implements CertAndKeyProvider
{

  /**
   * Map holding keys.
   */
  private final Map<String, byte[]> keyMap = new HashMap<>();

  /**
   * Reference to single instance.
   */
  private static LocalCertAndKeyProvider INSTANCE = null;

  /**
   * Private Constructor.
   */
  private LocalCertAndKeyProvider()
  {
    super();
  }

  /**
   * Gets single instance.
   *
   * @return single instance
   */
  public static LocalCertAndKeyProvider getInstance()
  {
    if (INSTANCE == null)
    {
      INSTANCE = new LocalCertAndKeyProvider();
    }
    return INSTANCE;
  }

  /** {@inheritDoc} */
  @Override
  public List<byte[]> getCertChain(String rootHolder, String termHolder) throws
    IOException
  {
    throw new RuntimeException("not implemented");
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getKeyByHolder(String holder)
  {
    AssertUtil.notNull(holder, "holder");
    return this.keyMap.get(holder);
  }

  /**
   * Adds a key to the map.
   *
   * @param holder holder of key, <code>null</code> not permitted
   * @param key key as byte-array
   * @throws IllegalArgumentException if holder <code>null</code>
   */
  public void addKey(String holder, byte[] key)
  {
    AssertUtil.notNull(holder, "holder");
    AssertUtil.notNullOrEmpty(key, "key");
    this.keyMap.put(holder, key);
  }

  /**
   * Removes a key from the map.
   *
   * @param holder holder of key, <code>null</code> not permitted
   * @throws IllegalArgumentException if holder <code>null</code>
   */
  void removeKey(String holder)
  {
    AssertUtil.notNull(holder, "holder");
    this.keyMap.remove(holder);
  }
}
