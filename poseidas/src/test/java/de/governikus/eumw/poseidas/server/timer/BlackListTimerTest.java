package de.governikus.eumw.poseidas.server.timer;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.Trigger;
import org.springframework.scheduling.TriggerContext;

import de.governikus.eumw.config.EidasMiddlewareConfig;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;


@ExtendWith(MockitoExtension.class)
class BlackListTimerTest
{

  @Mock
  private TriggerContext triggerContext;

  @Mock
  private PermissionDataHandling permissionDataHandling;

  @Mock
  private ConfigurationService configurationService;

  private BlackListTimer blackListTimer;

  @BeforeEach
  void setUp()
  {
    blackListTimer = new BlackListTimer(permissionDataHandling, configurationService);
  }


  @Test
  void testBlackListRunnable()
  {
    blackListTimer.run();
    Mockito.verify(permissionDataHandling, Mockito.times(1)).renewBlackList(true);
  }

  @Test
  void testBlackListTriggerWithInitialDelay()
  {
    Trigger blackListTrigger = blackListTimer.getBlackListTrigger();
    Mockito.when(triggerContext.lastScheduledExecutionTime()).thenReturn(null);
    Mockito.when(triggerContext.lastCompletionTime()).thenReturn(null);
    Instant now = Instant.now();
    Mockito.when(triggerContext.getClock()).thenReturn(Clock.fixed(now, Clock.systemDefaultZone().getZone()));
    Date nextExecutionTime = blackListTrigger.nextExecutionTime(triggerContext);
    Assertions.assertNotNull(nextExecutionTime);
    Assertions.assertEquals(Date.from(now.plus(Duration.ofHours(2))), nextExecutionTime);
  }

  @Test
  void testBlackListTriggerWithValuesFromConfig()
  {
    Trigger blackListTrigger = blackListTimer.getBlackListTrigger();
    Instant now = Instant.now();
    Mockito.when(triggerContext.lastScheduledExecutionTime()).thenReturn(Date.from(now));
    Mockito.when(triggerContext.lastCompletionTime()).thenReturn(Date.from(now));
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(getConfiguration()));
    Date nextExecutionTime = blackListTrigger.nextExecutionTime(triggerContext);
    Assertions.assertNotNull(nextExecutionTime);
    Assertions.assertEquals(Date.from(now.plus(Duration.ofHours(36))), nextExecutionTime);
  }

  @Test
  void testBlackListTriggerWithDefaultValues()
  {
    Trigger blackListTrigger = blackListTimer.getBlackListTrigger();
    Instant now = Instant.now();
    Mockito.when(triggerContext.lastScheduledExecutionTime()).thenReturn(Date.from(now));
    Mockito.when(triggerContext.lastCompletionTime()).thenReturn(Date.from(now));
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.empty());
    Date nextExecutionTime = blackListTrigger.nextExecutionTime(triggerContext);
    Assertions.assertNotNull(nextExecutionTime);
    Assertions.assertEquals(Date.from(now.plus(Duration.ofHours(2))), nextExecutionTime);
  }

  private EidasMiddlewareConfig getConfiguration()
  {
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    TimerTypeCertRenewal timerTypeCertRenewal = new TimerTypeCertRenewal(42, TimerUnit.HOURS, 20);
    TimerType timerType = new TimerType(36, TimerUnit.HOURS);
    TimerConfigurationType timerConfigurationType = new TimerConfigurationType(timerTypeCertRenewal, timerType,
                                                                               timerType, timerType);
    eidConfiguration.setTimerConfiguration(timerConfigurationType);
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);
    return eidasMiddlewareConfig;
  }
}
