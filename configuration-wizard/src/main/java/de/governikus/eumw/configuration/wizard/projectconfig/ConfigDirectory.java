/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.configuration.wizard.projectconfig;

import java.util.Observable;

import org.apache.commons.lang3.StringUtils;

import lombok.Data;


/**
 * project: eumw <br>
 * author Pascal Knueppel <br>
 * created at: 29.03.2018 - 08:59 <br>
 * <br>
 * this bean is used to determine or to reset the configuration directory. Chosen was this solution to have an
 * easier workout with JUnit tests while letting the complexity of the main program untouched
 */
@Data
public class ConfigDirectory extends Observable
{

  /**
   * this value is an optional value that will tell us where the configuration should be stored in the end or
   * read at system startup
   */
  private String configDirectoryValue;

  public ConfigDirectory(String configDirectory)
  {
    setConfigDirectory(configDirectory);
  }

  /**
   * @see #configDirectoryValue
   */
  public String getConfigDirectory()
  {
    return StringUtils.isBlank(configDirectoryValue) ? null : configDirectoryValue;
  }

  /**
   * @see #configDirectoryValue
   */
  public void setConfigDirectory(String configDirectory)
  {
    if (StringUtils.isBlank(configDirectory))
    {
      this.configDirectoryValue = null;
    }
    else
    {
      StringBuilder configurationDirectory = new StringBuilder(configDirectory);
      if (!configurationDirectory.toString().endsWith("/"))
      {
        configurationDirectory.append('/');
      }
      this.configDirectoryValue = configurationDirectory.toString();
    }
    super.setChanged();
    super.notifyObservers(this.configDirectoryValue);
  }
}
