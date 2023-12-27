package de.governikus.eumw.poseidas.server.idprovider.config;

import lombok.Data;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;


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
