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


/**
 * Lock to synchronize CVC updates over several parallel instances.
 *
 * @author tautenhahn
 */
@Entity
public class CVCUpdateLock implements Serializable
{

  private static final long serialVersionUID = 134472374L;

  /**
   * Create instance setting the fields.
   *
   * @param serviceProvider
   * @param lockedAt
   */
  CVCUpdateLock(String serviceProvider, long lockedAt)
  {
    this.trustCenterUrl = serviceProvider;
    this.lockedAt = lockedAt;
  }

  /**
   * Create blank instance - to be used by application server exclusively
   */
  public CVCUpdateLock()
  {
    // nothing to do
  }

  // Stores the service provider. In earlier versions, this field was used to store a trust center
  // URL, hence the name. In order to avoid the need to change the database, the name was kept.
  @Id
  private String trustCenterUrl;

  private long lockedAt;

  /**
   * Return the service provider this lock is for.
   */
  public String getServiceProvider()
  {
    return trustCenterUrl;
  }

  /**
   * Return the creation time of this lock in milliseconds. Not that container transaction cannot be used for
   * removing out-dated locks because lock must be propagated before update transaction starts
   */
  public long getLockedAt()
  {
    return lockedAt;
  }

  /**
   * steal an out-dated lock
   *
   * @param lockedAt
   */
  public void setLockedAt(long lockedAt)
  {
    this.lockedAt = lockedAt;
  }

}
