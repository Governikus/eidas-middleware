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

import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;


/**
 * Entry in the certificate chain.
 *
 * @author tt
 */
@Entity
@Getter
@Setter
@EqualsAndHashCode(exclude = "terminalPermission")
public class CertInChain implements Serializable
{

  private static final long serialVersionUID = 1L;

  /**
   * cyclic dependency for WebSphere - terminalPermission is <strong>not</strong> a property of this object
   * <strong>not</strong> a cyclic dependency, but a bidirectional relationship terminalPermission is indeed not a
   * property of this object, but the relationship is maintained by the property refid of this object
   */
  @ManyToOne
  @JoinColumn(name = "refID", nullable = false, insertable = false, updatable = false)
  private TerminalPermission terminalPermission;

  @EmbeddedId
  private CertInChainPK key;

  @Lob
  private byte[] data;

}
