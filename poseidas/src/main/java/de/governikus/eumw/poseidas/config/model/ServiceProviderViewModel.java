package de.governikus.eumw.poseidas.config.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the configuration of the ServiceProvider
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ServiceProviderViewModel
{

  private String dvcaConfigurationName;

  private KeypairInfoHolder clientKeyPair;

  private String name;

  private boolean enabled;
}
