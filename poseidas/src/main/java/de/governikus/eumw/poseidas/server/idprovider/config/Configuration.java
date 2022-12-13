package de.governikus.eumw.poseidas.server.idprovider.config;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;


/**
 * Entity to persist the runtime configuration for the middleware, dvcas and service providers
 */
@Entity
@Data
public class Configuration
{

  @Id
  @Column(name = "id", nullable = false)
  private Long id;

  @Lob
  private byte[] xmlConfigBlob;

}
