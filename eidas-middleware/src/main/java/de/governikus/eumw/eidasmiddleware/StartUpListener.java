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

import java.sql.SQLException;
import java.util.Timer;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.InitializationException;

import de.governikus.eumw.eidasstarterkit.EidasSaml;
import de.governikus.eumw.poseidas.server.eidservice.EIDInternal;


/**
 * Application Lifecycle Listener implementation class StartUpListener
 */
@WebListener
public class StartUpListener implements ServletContextListener
{

  private static final Log LOG = LogFactory.getLog(StartUpListener.class);

  private SessionStore store;

  private SessionStoreCleanUpTask task;

  /**
   * Initialize a scheduler
   */
  private static final Timer SCHEDULER = new Timer();


  /**
   * Calculation of one minute
   */
  private static final int MINUTE = 1000 * 60;

  /**
   * Default constructor.
   */
  public StartUpListener(SessionStore sessionStore, SessionStoreCleanUpTask sessionStoreCleanUpTask)
  {
    super();
    this.store = sessionStore;
    this.task = sessionStoreCleanUpTask;
  }

  /**
   * @see ServletContextListener#contextDestroyed(ServletContextEvent)
   */
  @Override
  public void contextDestroyed(ServletContextEvent arg0)
  {
    // nothing
  }

  /**
   * @see ServletContextListener#contextInitialized(ServletContextEvent)
   */
  @Override
  public void contextInitialized(ServletContextEvent arg0)
  {
    try
    {
      EidasSaml.init();
    }
    catch (InitializationException e)
    {
      LOG.error("can not init OpenSAML", e);
    }

    try
    {
      store.setupDb();
    }
    catch (SQLException e)
    {
      LOG.error(e);
    }

    // clean the db after a minute and then every day

    SCHEDULER.schedule(task, MINUTE, SessionStore.DAY_IN_MILLISECONDS);

    EIDInternal.getInstance().init();
  }
}
