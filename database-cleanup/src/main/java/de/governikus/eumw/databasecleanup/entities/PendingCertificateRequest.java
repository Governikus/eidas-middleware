/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.databasecleanup.entities;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;

import org.hibernate.proxy.HibernateProxy;

import lombok.Getter;
import lombok.Setter;


/**
 * Holds certificate request data of requests which have been created but not yet answered. You might want to send these
 * request again or take other steps.
 *
 * @author tautenhahn
 */
@Entity
@Getter
@Setter
public class PendingCertificateRequest implements Serializable
{

  private static final long serialVersionUID = 7011177849844700896L;

  /**
   * Status values describing the step within the certificate download process.
   */
  public enum Status
  {
    /** request has been created - private key is in HSM (in database for test only) */
    CREATED,
    /** request has been sent and accepted by the BerCA service */
    SENT,
    /**
     * one step of the request process failed and some administrator should intervene - see additional info
     */
    FAILURE
  }

  @Id
  private String refID;

  @Lob
  private byte[] requestData;

  @Lob
  private byte[] privateKey;

  @Enumerated(EnumType.STRING)
  private Status status;

  @Column(length = 1024)
  private String additionalInfo;

  private String messageID;

  @Temporal(TemporalType.TIMESTAMP)
  private Date lastChanged;

  @Lob
  private byte[] newCvcDescription;

  @Override
  public final boolean equals(Object o)
  {
    if (this == o)
      return true;
    if (o == null)
      return false;
    Class<?> oEffectiveClass = o instanceof HibernateProxy hProxy
      ? hProxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
    Class<?> thisEffectiveClass = this instanceof HibernateProxy hProxy
      ? hProxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
    if (thisEffectiveClass != oEffectiveClass)
      return false;
    PendingCertificateRequest that = (PendingCertificateRequest)o;
    return getRefID() != null && Objects.equals(getRefID(), that.getRefID());
  }

  @Override
  public final int hashCode()
  {
    return this instanceof HibernateProxy hProxy ? hProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
      : getClass().hashCode();
  }
}
