package de.governikus.eumw.poseidas.config.model.forms;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

import de.governikus.eumw.config.ServiceProviderType;
import de.governikus.eumw.poseidas.config.validation.DvcaConfigNameExists;
import de.governikus.eumw.poseidas.config.validation.KeyPairNameExists;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Model to hold the configuration of the ServiceProvider
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ServiceProviderConfigModel
{

  @DvcaConfigNameExists
  private String dvcaConfigurationName;

  @KeyPairNameExists
  @NotEmpty(message = "Has to be selected")
  private String clientKeyPairName;

  @NotBlank(message = "May not be empty")
  private String name;

  private boolean enabled;

  public ServiceProviderType toServiceProviderType()
  {
    return new ServiceProviderType(name, enabled, name, dvcaConfigurationName, clientKeyPairName);
  }

  public ServiceProviderType toServiceProviderType(String cvcRefID)
  {
    return new ServiceProviderType(name, enabled, cvcRefID, dvcaConfigurationName, clientKeyPairName);
  }
}
