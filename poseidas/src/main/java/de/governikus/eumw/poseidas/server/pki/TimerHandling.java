/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.poseidas.server.pki;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.EnumMap;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;

import javax.management.JMException;
import javax.management.MBeanServer;
import javax.management.Notification;
import javax.management.ObjectName;
import javax.management.timer.Timer;

import de.governikus.eumw.poseidas.config.schema.TimerConfigurationType;
import de.governikus.eumw.poseidas.config.schema.TimerType;
import de.governikus.eumw.poseidas.server.idprovider.accounting.SNMPDelegate;
import de.governikus.eumw.poseidas.server.idprovider.accounting.SNMPDelegate.OID;
import de.governikus.eumw.poseidas.server.idprovider.config.PoseidasConfigurator;
import lombok.extern.slf4j.Slf4j;


/**
 * Set and execute all the timers needed for permission data renewal. The timers are scheduled with odd
 * offsets to avoid two timers being executed simultaneously.
 * 
 * @author tautenhahn
 */
@Slf4j
public class TimerHandling implements TimerHandlingMBean
{

  private ObjectName oname;
  
  private ObjectName timerOname;

  private final PermissionDataHandlingMBean permissionDataHandling;

  private MBeanServer server;

  private final TerminalPermissionAO facade;

  private String lastTask = "";

  private final int generalOffset = new GregorianCalendar().get(Calendar.MINUTE);

  private enum NotificationType
  {
    RENEW_MASTER_AND_DEFECT_LIST,
    RENEW_CVCS,
    RENEW_BLACKLIST,
    RENEW_BLACKLIST_DELTA,
    CHECK_KEY_LOCKS,
    WATCHDOG
  }

  private static final int[] CALENDAR_FIELDS = new int[]{Calendar.MILLISECOND, Calendar.SECOND,
                                                         Calendar.MINUTE, Calendar.HOUR_OF_DAY,
                                                         Calendar.DAY_OF_MONTH, Calendar.MONTH};


  private final Map<NotificationType, Date> nextScheduledDate = new EnumMap<>(NotificationType.class);

  private final Map<NotificationType, Integer> offset = new EnumMap<>(NotificationType.class);

  private final HSMServiceHolder hsmServiceHolder;

  /**
   * Create new instance
   * 
   * @param permissionDataHandling object to be called by the timers
   * @param hsmServiceHolder
   */
  TimerHandling(PermissionDataHandlingMBean permissionDataHandling,
                       HSMServiceHolder hsmServiceHolder,
                       TerminalPermissionAO facade)
  {
    this.permissionDataHandling = permissionDataHandling;
    this.facade = facade;
    this.hsmServiceHolder = hsmServiceHolder;
    offset.put(NotificationType.RENEW_BLACKLIST, Integer.valueOf(2));
    offset.put(NotificationType.RENEW_BLACKLIST_DELTA, Integer.valueOf(43));
    offset.put(NotificationType.RENEW_CVCS, Integer.valueOf(32));
    offset.put(NotificationType.RENEW_MASTER_AND_DEFECT_LIST, Integer.valueOf(37));
    offset.put(NotificationType.CHECK_KEY_LOCKS, Integer.valueOf(75));
  }

  @Override
  public void handleNotification(Notification notification, Object handback)
  {
    NotificationType type = NotificationType.valueOf(notification.getType());
    if (nextScheduledDate.containsKey(type))
    {

      Date nextPlannedDate = nextScheduledDate.remove(type);
      Calendar referenceCal = Calendar.getInstance();
      referenceCal.add(Calendar.SECOND, -5);
      if (type.name().equals(lastTask) && nextPlannedDate.before(referenceCal.getTime()))
      {
        log.warn("Already exceeded next scheduled date for {}, skipping this execution", type);
        try
        {
          scheduleNextNotification(type, false);
        }
        catch (JMException e)
        {
          log.error("problem while setting next {} schedule time", type, e);
        }
        return;
      }
    }
    else
    {
      log.warn("List is empty {}", type);
    }
    log.info("start with running task: {}", type.name());
    if (type.equals(NotificationType.WATCHDOG))
    {
      checkNotificationScheduledInFuture();
      log.debug("ending with running task: {}", type.name());
      return;
    }
    try
    {
      scheduleNextNotification(type, false);
    }
    catch (JMException e)
    {
      log.error("problem while setting next {} schedule time", type, e);
    }
    try
    {
      lastTask = type.name();
      switch (type)
      {
        case RENEW_BLACKLIST:
          permissionDataHandling.renewBlackList(false);
          break;
        case RENEW_BLACKLIST_DELTA:
          permissionDataHandling.renewBlackList(true);
          break;
        case RENEW_CVCS:
          permissionDataHandling.renewOutdatedCVCs();
          break;
        case RENEW_MASTER_AND_DEFECT_LIST:
          permissionDataHandling.renewMasterAndDefectList();
          break;
        case CHECK_KEY_LOCKS:
          log.debug("checking locks for {}", InetAddress.getLocalHost().toString());
          List<ChangeKeyLock> lockList = facade.getAllChangeKeyLocksByInstance(true);
          if (hsmServiceHolder.isServiceSet())
          {
            for ( ChangeKeyLock lock : lockList )
            {
              if (!hsmServiceHolder.isWorkingOnKey(lock.getKeyName()))
              {
                facade.releaseChangeKeyLock(lock);
                log.debug("lock for key {} released", lock.getKeyName());
              }
            }
          }
          List<ChangeKeyLock> foreignLockList = facade.getAllChangeKeyLocksByInstance(false);
          for ( ChangeKeyLock lock : foreignLockList )
          {
            if (facade.obtainChangeKeyLock(lock.getKeyName(), lock.getType()) != null)
            {
              if (lock.getType() == ChangeKeyLock.TYPE_DELETE)
              {
                hsmServiceHolder.deleteKey(lock.getKeyName());
                log.debug("lock for key {} stolen, deleting key", lock.getKeyName());
              }
              else
              {
                hsmServiceHolder.distributeKey(lock.getKeyName());
                log.debug("lock for key {} stolen, distributing key", lock.getKeyName());
              }
            }
          }
          break;
        default:
          log.error("unimplemented case {}", type);
      }
    }
    catch (Throwable t)
    {
      log.error("Something went wrong while running the timer", t);
    }
    log.info("ending with running task: {}", type.name());
  }

  private Integer watchdogNotificationId;

  private boolean timerRegistered = false;

  private void scheduleNextNotification(NotificationType type, boolean soon) throws JMException
  {
    if (nextScheduledDate.containsKey(type))
    {
      return;
    }
    Calendar calendar = new GregorianCalendar();
    if (soon)
    {
      addInitialOffset(type, calendar);
    }
    else
    {
      addInterval(type, calendar);
    }
    log.info("schedule next {} at {}", type, calendar.getTime());
    Object[] params = new Object[]{type.toString(), "", null, calendar.getTime()};
    String[] signature = new String[]{String.class.getName(), String.class.getName(), Object.class.getName(),
                                      Date.class.getName()};
    server.invoke(timerOname, "addNotification", params, signature);
    nextScheduledDate.put(type, calendar.getTime());
  }

  /**
   * Returns the configuration for the given timer type.
   * 
   * @param type
   */
  private TimerType getTimerForNotification(NotificationType type)
  {
    TimerConfigurationType timerConfig = PoseidasConfigurator.getInstance()
                                                           .getCurrentConfig()
                                                           .getTimerConfiguration();
    switch (type)
    {
      case RENEW_BLACKLIST:
        TimerType tt = new TimerType();
        tt.setUnit(Calendar.MONTH);
        tt.setLength(1);
        return tt;
      case RENEW_BLACKLIST_DELTA:
        return timerConfig.getBlacklistRenewal();
      case RENEW_CVCS:
        return timerConfig.getCertRenewal();
      case RENEW_MASTER_AND_DEFECT_LIST:
        return timerConfig.getMasterAndDefectListRenewal();
      case CHECK_KEY_LOCKS:
        // check of key locks must be done in short intervals, checks for HSM could be a little longer (but
        // not much), think of making configurable
        tt = new TimerType();
        tt.setUnit(Calendar.MINUTE);
        tt.setLength(1);
        return tt;
      case WATCHDOG:
        // can not configure watchdog and this is not needed.
        break;
      default:
        log.error("unimplemented notification type {}", type);
    }
    return null;
  }

  /**
   * Set the given calendar to the next date matching offset and interval for that timer type. The output
   * should satisfy:
   * <ul>
   * <li>the time between 2 consecutive schedule dates of one type is exactly the specified interval</li>
   * <li>on the same instance of poseidas, tho timers of different type are never started simultaneously, there
   * is some time left for each timer to finish before the next starts.</li>
   * <li>different instances of poseidas do not automatically start their timers of same type at the same
   * time.</li>
   * </ul>
   * 
   * @param type
   * @param calendar
   */
  private void addInterval(NotificationType type, Calendar calendar)
  {
    calendar.add(Calendar.MINUTE, -generalOffset);
    TimerType timerType = getTimerForNotification(type);
    if (timerType != null)
    {
      int unit = timerType.getUnit();
      int length = timerType.getLength();
      for ( int i = 0 ; i < CALENDAR_FIELDS.length - 1 ; i++ )
      {
        if (CALENDAR_FIELDS[i + 1] == unit)
        {
          calendar.set(CALENDAR_FIELDS[i], offset.get(type).intValue());
          break;
        }
        calendar.set(CALENDAR_FIELDS[i], 0);
      }
      if (unit == Calendar.MINUTE)
      {
        calendar.set(Calendar.MINUTE, calendar.get(Calendar.MINUTE) / length * length);
      }
      if (calendar.getTimeInMillis() - 1000L * 60 * 9 <= System.currentTimeMillis() - 60000L * generalOffset)
      {
        calendar.add(unit, length);
      }
      calendar.add(Calendar.MINUTE, generalOffset);
    }
  }

  /**
   * Add an offset to the given calendar for scheduling the first timer of each kind. The timers are set 10
   * seconds, 2 minutes and 7 minutes after registration, respectively. Further timers are scheduled within
   * the predefined intervals.
   */
  private void addInitialOffset(NotificationType type, Calendar calendar)
  {
    switch (type)
    {
      case RENEW_BLACKLIST:
        calendar.add(Calendar.DAY_OF_MONTH, 2);
        break;
      case RENEW_BLACKLIST_DELTA:
        calendar.add(Calendar.MINUTE, 2);
        break;
      case RENEW_CVCS:
        calendar.add(Calendar.SECOND, 10);
        break;
      case RENEW_MASTER_AND_DEFECT_LIST:
        calendar.add(Calendar.MINUTE, 7);
        break;
      case CHECK_KEY_LOCKS:
        calendar.add(Calendar.SECOND, 25);
        break;
      default:
        log.error("unimplemented case ", type);
    }
  }

  @Override
  public void postDeregister()
  {
    if (watchdogNotificationId != null)
    {
      try
      {
        timerOname = new ObjectName(oname.getDomain() + ":service=timer");
        Object[] param = new Object[]{watchdogNotificationId};
        String[] signature = new String[]{Integer.class.getName()};
        server.invoke(timerOname, "removeNotification", param, signature);
        log.debug("Successfully deregistered notification for watchdog");
        watchdogNotificationId = null;
        if (timerRegistered)
        {
          server.unregisterMBean(timerOname);
        }
      }
      catch (JMException e)
      {
        log.debug("was not able to unregister timer watchdog - not a problem if server stops anyway");
      }
    }
  }

  @Override
  public void postRegister(Boolean registrationDone)
  {
    try
    {
      timerOname = new ObjectName(oname.getDomain() + ":service=timer");

      if (!server.isRegistered(timerOname))
      {
        server.registerMBean(new Timer(), timerOname);
        server.invoke(timerOname, "start", null, null);
        server.addNotificationListener(timerOname, this, null, null);
        timerRegistered = true;
      }
      scheduleNextNotification(NotificationType.RENEW_BLACKLIST_DELTA, true);
      scheduleNextNotification(NotificationType.RENEW_BLACKLIST, false);
      scheduleNextNotification(NotificationType.RENEW_CVCS, true);
      scheduleNextNotification(NotificationType.RENEW_MASTER_AND_DEFECT_LIST, true);
      scheduleNextNotification(NotificationType.CHECK_KEY_LOCKS, true);
      Object[] params = new Object[]{NotificationType.WATCHDOG.toString(), "", null, new Date(),
                                     Long.valueOf(1000L * 60 * 30)};
      String[] signature = new String[]{String.class.getName(), String.class.getName(),
                                        Object.class.getName(), Date.class.getName(), long.class.getName()};
      watchdogNotificationId = (Integer)server.invoke(timerOname, "addNotification", params, signature);
    }
    catch (JMException e)
    {
      log.error("Problem while creating and register of timer", e);
    }
  }


  @Override
  public void preDeregister() throws Exception
  {
    // nothing to do here
  }

  @Override
  public ObjectName preRegister(MBeanServer assignedServer, ObjectName name) throws Exception
  {
    oname = name;
    server = assignedServer;
    return name;
  }

  private void checkNotificationScheduledInFuture()
  {
    Date refDate = new Date(System.currentTimeMillis() - 1000L * 10 * 60);
    for ( Map.Entry<NotificationType, Date> entry : nextScheduledDate.entrySet() )
    {
      if (entry.getValue().before(refDate))
      {
        log.error("No notification for {} found, scheduling it again", entry.getKey());
        try
        {
          scheduleNextNotification(entry.getKey(), true);
        }
        catch (JMException e)
        {
          log.error("Cannot re-schedule notification for {}", entry.getKey());
          SNMPDelegate.getInstance()
                      .sendSNMPTrap(OID.CANNOT_RESCHEDULE_TIMERS,
                                    SNMPDelegate.CANNOT_RESCHEDULE_TIMERS + " " + entry.getKey().toString());
        }
      }
    }
    log.info("Notification timer successfully checked by watch dog");
  }

  @Override
  public Date getNextDate(String type)
  {
    return nextScheduledDate.get(NotificationType.valueOf(type));
  }

  @Override
  public List<String> getTimerTypes()
  {
    List<String> result = new ArrayList<>();
    for ( NotificationType type : NotificationType.values() )
    {
      result.add(type.toString());
    }
    return result;
  }

}
