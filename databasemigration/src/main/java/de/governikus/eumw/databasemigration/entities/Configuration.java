package de.governikus.eumw.databasemigration.entities;

import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;

import org.hibernate.proxy.HibernateProxy;

import lombok.Getter;
import lombok.Setter;


/**
 * Entity to persist the runtime configuration for the middleware, dvcas and service providers
 */
@Entity
@Getter
@Setter
public class Configuration
{

  @Id
  @Column(name = "id", nullable = false)
  private Long id;

  @Lob
  private byte[] xmlConfigBlob;

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
    Configuration that = (Configuration)o;
    return getId() != null && Objects.equals(getId(), that.getId());
  }

  @Override
  public final int hashCode()
  {
    return this instanceof HibernateProxy hProxy ? hProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
      : getClass().hashCode();
  }
}
