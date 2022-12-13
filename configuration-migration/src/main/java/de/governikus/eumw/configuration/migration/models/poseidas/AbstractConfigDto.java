/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.migration.models.poseidas;


/**
 * Wrapper for CoreConfigurationType to make generic MBean look better.
 *
 * @author tt
 */
public abstract class AbstractConfigDto<T>
{



  /**
   * JAXB created object wrapped by this class
   */
  protected T jaxbConfig;

  /**
   * For creation you need an object to wrap.
   *
   * @param jaxBConfig
   */
  protected AbstractConfigDto(T jaxBConfig)
  {
    setJaxbConfig(jaxBConfig);
  }

  /**
   * Set the configuration object. All attributes derived from that configuration must be updated too.
   *
   * @param jaxBConfig
   */
  protected abstract void setJaxbConfig(T jaxBConfig);

  /**
   * Return the wrapped (and updated) object.
   */
  public abstract T getJaxbConfig();
}
