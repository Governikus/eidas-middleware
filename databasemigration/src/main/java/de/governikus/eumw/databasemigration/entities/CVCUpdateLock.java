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
 * Lock to synchronize CVC updates over several parallel instances.
 *
 * @author tautenhahn
 */
@Entity
@Data
public class CVCUpdateLock implements Serializable
{

  private static final long serialVersionUID = 134472374L;


  // Stores the service provider. In earlier versions, this field was used to store a trust center
  // URL, hence the name. In order to avoid the need to change the database, the name was kept.
  @Id
  private String trustCenterUrl;

  private long lockedAt;


}
