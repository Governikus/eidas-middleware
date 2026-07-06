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
import java.util.Objects;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;

import org.hibernate.proxy.HibernateProxy;

import lombok.Getter;
import lombok.Setter;


/**
 * Lock for synchronizing changes in keys stored in HSM instances.
 *
 * @author Arne Stahlbock, ast@bos-bremen.de
 */
@Entity
@Getter
@Setter
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
    KeyArchive that = (KeyArchive)o;
    return getKeyName() != null && Objects.equals(getKeyName(), that.getKeyName());
  }

  @Override
  public final int hashCode()
  {
    return this instanceof HibernateProxy hProxy ? hProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
      : getClass().hashCode();
  }
}
