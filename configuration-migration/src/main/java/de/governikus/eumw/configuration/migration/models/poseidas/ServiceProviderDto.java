/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.configuration.migration.models.poseidas;

import de.governikus.eumw.poseidas.config.schema.ServiceProviderType;


/**
 * Wrapper for class ServiceProviderType to grant easier access to key and certificate data
 *
 * @author tt
 */
public class ServiceProviderDto extends AbstractConfigDto<ServiceProviderType>
{

  private EPAConnectorConfigurationDto epaConnectorConfigurationDTO;

  /**
   * create a new empty instance
   *
   * @param entityID primary key
   */
  public ServiceProviderDto(String entityID)
  {
    super(new ServiceProviderType());
    jaxbConfig.setEntityID(entityID);
    jaxbConfig.setEnabled(Boolean.FALSE);
  }

  /**
   * create an instance wrapping a given JAXB configuration object
   *
   * @param jaxbConfig
   */
  ServiceProviderDto(ServiceProviderType jaxbConfig)
  {
    super(jaxbConfig);
  }

  @Override
  protected void setJaxbConfig(ServiceProviderType jaxbConfig)
  {
    this.jaxbConfig = jaxbConfig;
    if (jaxbConfig.getEPAConnectorConfiguration() != null)
    {
      epaConnectorConfigurationDTO = new EPAConnectorConfigurationDto(jaxbConfig.getEPAConnectorConfiguration(), this);
    }
  }

  /**
   * update and return the wrapped JAXB object
   */
  @Override
  public ServiceProviderType getJaxbConfig()
  {
    jaxbConfig.setEPAConnectorConfiguration(epaConnectorConfigurationDTO == null ? null
      : epaConnectorConfigurationDTO.getJaxbConfig());
    return jaxbConfig;
  }

  /**
   * return the configuration object for passport based authentication
   */
  public EPAConnectorConfigurationDto getEpaConnectorConfiguration()
  {
    return epaConnectorConfigurationDTO;
  }

  /**
   * Return the name of this service provider.s
   */
  public String getEntityID()
  {
    return jaxbConfig.getEntityID();
  }

  /**
   * Return true if the represented provider is allowed to use this server. Only in this case, this configuration part
   * should be included into the warmup test.
   */
  public boolean isEnabled()
  {
    return jaxbConfig.isEnabled();
  }
}
