/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki.entities;

import java.io.Serializable;
import java.util.Objects;

import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Lob;

import org.hibernate.proxy.HibernateProxy;

import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Entity
public class RequestSignerCertificate implements Serializable
{

  private static final long serialVersionUID = 8846802904967943625L;

  @EmbeddedId
  private CertInChainPK key;

  @Lob
  private byte[] privateKey;

  @Lob
  private byte[] x509RequestSignerCertificate;

  private Status status;

  public enum Status
  {
    READY_TO_SEND, FAILURE
  }

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
    RequestSignerCertificate that = (RequestSignerCertificate)o;
    return getKey() != null && Objects.equals(getKey(), that.getKey());
  }

  @Override
  public final int hashCode()
  {
    return Objects.hash(key);
  }
}
