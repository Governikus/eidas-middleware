/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.databasemigration.entities;

import java.io.Serializable;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

import lombok.Data;


/**
 * Lock for synchronizing changes in keys stored in HSM instances.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Entity
@Data
public class ChangeKeyLock implements Serializable
{

  private static final long serialVersionUID = 1828942536669759458L;

  static final String QUERY_NAME_GETOWNLOCKS = "getOwnLocks";

  static final String QUERY_NAME_GETFOREIGNLOCKS = "getForeignLocks";

  static final String PARAM_IP = "pIp";

  /**
   * Constant for key deletion lock type.
   */
  public static final int TYPE_DELETE = 0;

  /**
   * Constant for key distribution lock type.
   */
  public static final int TYPE_DISTRIBUTE = 1;

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
}
