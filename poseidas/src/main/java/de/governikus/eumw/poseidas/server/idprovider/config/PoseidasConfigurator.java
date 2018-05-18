/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.idprovider.config;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;

import javax.xml.bind.JAXBException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.google.common.base.Strings;

import de.governikus.eumw.eidascommon.Utils;


/**
 * Provides configuration for poseidas. Separate configurations may be needed for project specific
 * business delegates. All "worker" classes in poseidas shall not keep an own copy of the configuration (for
 * instance in serialized form) but re-fetch the configuration object from here if necessary.
 * 
 * @author TT
 */
public final class PoseidasConfigurator
{

  private static final Log LOG = LogFactory.getLog(PoseidasConfigurator.class);

  private static PoseidasConfigurator instance = new PoseidasConfigurator();

  private CoreConfigurationDto currentVersion = null;

  private long lastUpdate;

  private PoseidasConfigurator()
  {
    super();
  }

  /**
   * Singleton getter. Having several instances in a cluster is no problem.
   */
  public static PoseidasConfigurator getInstance()
  {
    return instance;
  }

  /**
   * Return the currently active configuration. Call this method only for one-step-processes. Otherwise, first
   * get the version of the configuration the process should run with.
   */
  public CoreConfigurationDto getCurrentConfig()
  {
    if (lastUpdate + 10000L < System.currentTimeMillis() || currentVersion == null)
    {
      try
      {
        lastUpdate = System.currentTimeMillis();
        currentVersion = loadConfig();
      }
      catch (FileNotFoundException e)
      {
        LOG.error("cannot get current configuration version", e);
      }
      catch (JAXBException e)
      {
        LOG.error("cannot get current configuration version", e);
      }
    }
    return currentVersion;
  }

  /**
   * Return the configuration of a given version
   * 
   * @return null if there is no such configuration
   */
  private CoreConfigurationDto loadConfig() throws FileNotFoundException, JAXBException
  {
    File configDir = null;
    if (!Strings.isNullOrEmpty(System.getProperty("spring.config.location")))
    {
      configDir = new File(Utils.prepareSpringConfigLocation(System.getProperty("spring.config.location")));
    }
    else if (!Strings.isNullOrEmpty(System.getenv("SPRING_CONFIG_LOCATION")))
    {
      configDir = new File(Utils.prepareSpringConfigLocation(System.getenv("SPRING_CONFIG_LOCATION")));
    }
    else
    {
      configDir = new File(System.getProperty("user.dir"), "config");
    }

    File configfile = new File(configDir, "POSeIDAS.xml");
    return CoreConfigurationDto.readFrom(new FileReader(configfile));
  }
}
