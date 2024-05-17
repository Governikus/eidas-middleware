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

import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;


/**
 * Entry in the certificate chain.
 *
 * @author tt
 */
@Entity
public class CertInChain implements Serializable
{

  private static final long serialVersionUID = 1L;

  /**
   * cyclic dependency for WebSphere - terminalPermission is <strong>not</strong> a property of this object
   * <strong>not</strong> a cyclic dependency, but a bidirectional relationship terminalPermission is indeed
   * not a property of this object, but the relationship is maintained by the property refid of this object
   */
  @ManyToOne
  @JoinColumn(name = "refID", nullable = false, insertable = false, updatable = false)
  private TerminalPermission terminalPermission;

  /**
   * @param terminalPermission parameter for WebSphere - not wanted in the model
   * @param key
   * @param data
   */
  public CertInChain(TerminalPermission terminalPermission, CertInChainPK key, byte[] data)
  {
    super();
    this.terminalPermission = terminalPermission;
    this.key = key;
    this.data = data;
  }

  /**
   * probably needed by application server
   */
  public CertInChain()
  {
    super();
  }

  /**
   * Return the primary key of this entity.
   */
  public CertInChainPK getKey()
  {
    return key;
  }

  /**
   * Return the serialized certificate.
   */
  public byte[] getData()
  {
    return data;
  }

  @EmbeddedId
  private CertInChainPK key;

  @Lob
  private byte[] data;

  /**
   * set certificate data
   */
  public void setData(byte[] data)
  {
    this.data = data;
  }

  /**
   * not wanted in the model
   *
   * @return the property terminalPermission
   */
  public TerminalPermission getTerminalPermission()
  {
    return terminalPermission;
  }

}
