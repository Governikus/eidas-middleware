/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.util.TimerTask;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


/**
 * @author hohnholt
 */
@Component
class SessionStoreCleanUpTask extends TimerTask
{

  private static final Log LOG = LogFactory.getLog(SessionStoreCleanUpTask.class);

  @Autowired
  private SessionStore store;

  @Override
  public void run()
  {
    try
    {
      store.cleanUp();
    }
    catch (Exception e)
    {
      LOG.warn("Can not run SessionStoreCleanUpTask ", e);
    }
  }
}
