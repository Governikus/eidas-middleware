/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.entities;

import java.io.Serializable;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;


/**
 * Lock for synchronizing changes in keys stored in HSM instances.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Entity
public class KeyArchive implements Serializable
{

  private static final long serialVersionUID = 7348530135916290397L;

  /**
   * Name of archived key.
   */
  @Id
  private String keyName = null;

  /**
   * CVC.
   */
  @Lob
  private byte[] cvc = null;

  /**
   * Key data (typically encrypted).
   */
  @Lob
  private byte[] privateKey = null;

  /**
   * Constructor setting key name and CVC.
   *
   * @param keyName name of key, <code>null</code> or empty not permitted
   * @param cvcBytes cvc as byte-array, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   */
  public KeyArchive(String keyName, byte[] cvcBytes)
  {
    AssertUtil.notNull(keyName, "key name");
    AssertUtil.notNull(cvcBytes, "cvc bytes");
    this.keyName = keyName;
    this.cvc = cvcBytes;
  }

  /**
   * Constructor setting key name.
   *
   * @param keyName name of key, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if any argument <code>null</code> or empty
   */
  public KeyArchive(String keyName)
  {
    AssertUtil.notNull(keyName, "key name");
    this.keyName = keyName;
  }

  /**
   * Empty constructor.
   */
  public KeyArchive()
  {
    super();
  }

  /**
   * Get name of key.
   *
   * @return name of key
   */
  public String getKeyName()
  {
    return this.keyName;
  }

  /**
   * Gets CVC as bytes.
   *
   * @return cvc bytes
   */
  public byte[] getCvc()
  {
    return this.cvc;
  }

  /**
   * Sets CVC.
   *
   * @param cvcBytes CVC as byte-array, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if cvcBytes <code>null</code> or empty
   */
  public void setCvc(byte[] cvcBytes)
  {
    AssertUtil.notNullOrEmpty(cvcBytes, "cvc bytes");
    this.cvc = cvcBytes;
  }

  /**
   * Get key data.
   *
   * @return key data
   */
  public byte[] getPrivateKey()
  {
    return this.privateKey;
  }

  /**
   * Sets private key.
   *
   * @param pkBytes private key as byte-array, <code>null</code> or empty not permitted
   * @throws IllegalArgumentException if pkBytes <code>null</code> or empty
   */
  public void setPrivateKey(byte[] pkBytes)
  {
    AssertUtil.notNullOrEmpty(pkBytes, "private key bytes");
    this.privateKey = pkBytes;
  }
}
