/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.io.Serializable;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQuery;

import de.governikus.eumw.poseidas.cardbase.AssertUtil;


/**
 * Lock for synchronizing changes in keys stored in HSM instances.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Entity
@NamedQuery(name = ChangeKeyLock.QUERY_NAME_GETOWNLOCKS, query = "SELECT l FROM ChangeKeyLock l WHERE l.autentIP = :"
                                                                 + ChangeKeyLock.PARAM_IP)
@NamedQuery(name = ChangeKeyLock.QUERY_NAME_GETFOREIGNLOCKS, query = "SELECT l FROM ChangeKeyLock l WHERE l.autentIP <> :"
                                                                     + ChangeKeyLock.PARAM_IP)
public class ChangeKeyLock implements Serializable
{

  private static final long serialVersionUID = 1828942536669759458L;

  static final String QUERY_NAME_GETOWNLOCKS = "getOwnLocks";

  static final String QUERY_NAME_GETFOREIGNLOCKS = "getForeignLocks";

  static final String PARAM_IP = "pIp";

  /**
   * Constant for key deletion lock type.
   */
  static final int TYPE_DELETE = 0;

  /**
   * Constant for key distribution lock type.
   */
  static final int TYPE_DISTRIBUTE = 1;

  /**
   * Name of key to be locked.
   */
  @Id
  private String keyName = null;

  /**
   * IP of lock controller.
   */
  private String autentIP = null;

  /**
   * Lock timestamp.
   */
  private long lockedAt;

  /**
   * Lock type.
   */
  private int type;

  /**
   * Constructor setting the key name.
   *
   * @param keyName name of key to be locked, <code>null</code> or empty not permitted
   * @param autentIP identifier for Autent instance holding lock, <code>null</code> or empty not permitted
   * @param lockedAt timestamp
   * @param type type, must be one of {@link #TYPE_DELETE} or {@link #TYPE_DISTRIBUTE}
   * @throws IllegalArgumentException if wrong type given
   */
  ChangeKeyLock(String keyName, String autentIP, long lockedAt, int type)
  {
    AssertUtil.notNull(keyName, "key name");
    AssertUtil.notNull(autentIP, "Autent instance identifier");
    if (type != TYPE_DELETE && type != TYPE_DISTRIBUTE)
    {
      throw new IllegalArgumentException("unknown lock type given");
    }
    this.keyName = keyName;
    this.lockedAt = lockedAt;
    this.type = type;
    this.autentIP = autentIP;
  }

  /**
   * Empty constructor.
   */
  public ChangeKeyLock()
  {
    super();
  }

  /**
   * Get name of locked key.
   *
   * @return name of locked key
   */
  public String getKeyName()
  {
    return this.keyName;
  }

  /**
   * Get IP of poseidas instance which controls the lock.
   *
   * @return IP of lock controlling instance
   */
  public String getAutentIP()
  {
    return this.autentIP;
  }

  /**
   * Set IP of poseidas instance which controls the lock.
   *
   * @param autentIP IP of lock controlling instance
   */
  public void setAutentIP(String autentIP)
  {
    this.autentIP = autentIP;
  }

  /**
   * Get timestamp of lock.
   *
   * @return timestamp
   */
  public long getLockedAt()
  {
    return this.lockedAt;
  }

  /**
   * Set timestamp of lock.
   *
   * @param lockedAt timestamp
   */
  public void setLockedAt(long lockedAt)
  {
    this.lockedAt = lockedAt;
  }

  /**
   * Gets type of lock.
   *
   * @return type
   */
  public int getType()
  {
    return this.type;
  }
}
