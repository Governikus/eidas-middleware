/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import javax.annotation.PostConstruct;

import org.opensaml.core.config.InitializationException;
import org.springframework.stereotype.Component;

import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;
import lombok.extern.slf4j.Slf4j;


/**
 * Application Lifecycle Listener implementation class StartUpListener
 */
@Component
@Slf4j
public class StartUpListener
{


  @PostConstruct
  public void contextInitialized()
  {
    try
    {
      EidasSaml.init();
    }
    catch (InitializationException e)
    {
      log.error("Cannot initialize OpenSAML", e);
    }

    EIDInternal.getInstance().init();
  }
}
