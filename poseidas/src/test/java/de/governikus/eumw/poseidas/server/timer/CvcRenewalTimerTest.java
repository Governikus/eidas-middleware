package de.governikus.eumw.poseidas.server.timer;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
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
import de.governikus.eumw.config.EntanglementTimerType;
import de.governikus.eumw.config.TimerConfigurationType;
import de.governikus.eumw.config.TimerType;
import de.governikus.eumw.config.TimerTypeCertRenewal;
import de.governikus.eumw.config.TimerUnit;
import de.governikus.eumw.poseidas.server.idprovider.config.ConfigurationService;
import de.governikus.eumw.poseidas.server.pki.PermissionDataHandling;


@ExtendWith(MockitoExtension.class)
class CvcRenewalTimerTest
{

  @Mock
  private TriggerContext triggerContext;

  @Mock
  private PermissionDataHandling permissionDataHandling;

  @Mock
  private ConfigurationService configurationService;

  private CvcRenewalTimer cvcRenewalTimer;

  @BeforeEach
  void setUp()
  {
    cvcRenewalTimer = new CvcRenewalTimer(permissionDataHandling, configurationService);
  }

  @Test
  void testCVCRenewalRunnable()
  {
    cvcRenewalTimer.run();
    Mockito.verify(permissionDataHandling, Mockito.times(1)).renewOutdatedCVCs();
  }

  @Test
  void testCvcRenewalTriggerWithInitialDelay()
  {
    Trigger cvcRenewalTrigger = cvcRenewalTimer.getCvcRenewalTrigger(new ArrayList<>());
    Mockito.when(triggerContext.lastScheduledExecutionTime()).thenReturn(null);
    Mockito.when(triggerContext.lastCompletionTime()).thenReturn(null);
    Instant now = Instant.now();
    Mockito.when(triggerContext.getClock()).thenReturn(Clock.fixed(now, Clock.systemDefaultZone().getZone()));
    Date nextExecutionTime = cvcRenewalTrigger.nextExecutionTime(triggerContext);
    Assertions.assertNotNull(nextExecutionTime);
    Assertions.assertEquals(Date.from(now.plusSeconds(5L)), nextExecutionTime);
  }

  @Test
  void testCvcRenewalTriggerWithValuesFromConfig()
  {
    Trigger cvcRenewalTrigger = cvcRenewalTimer.getCvcRenewalTrigger(new ArrayList<>());
    Instant now = Instant.now();
    Mockito.when(triggerContext.lastScheduledExecutionTime()).thenReturn(Date.from(now));
    Mockito.when(triggerContext.lastCompletionTime()).thenReturn(Date.from(now));
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.of(getConfiguration()));
    Date nextExecutionTime = cvcRenewalTrigger.nextExecutionTime(triggerContext);
    Assertions.assertNotNull(nextExecutionTime);
    Assertions.assertEquals(Date.from(now.plus(Duration.ofHours(42))), nextExecutionTime);
  }

  @Test
  void testCvcRenewalTriggerWithDefaultValues()
  {
    Trigger cvcRenewalTrigger = cvcRenewalTimer.getCvcRenewalTrigger(new ArrayList<>());
    Instant now = Instant.now();
    Mockito.when(triggerContext.lastScheduledExecutionTime()).thenReturn(Date.from(now));
    Mockito.when(triggerContext.lastCompletionTime()).thenReturn(Date.from(now));
    Mockito.when(configurationService.getConfiguration()).thenReturn(Optional.empty());
    Date nextExecutionTime = cvcRenewalTrigger.nextExecutionTime(triggerContext);
    Assertions.assertNotNull(nextExecutionTime);
    Assertions.assertEquals(Date.from(now.plus(Duration.ofHours(1))), nextExecutionTime);
  }

  private EidasMiddlewareConfig getConfiguration()
  {
    EidasMiddlewareConfig eidasMiddlewareConfig = new EidasMiddlewareConfig();
    EidasMiddlewareConfig.EidConfiguration eidConfiguration = new EidasMiddlewareConfig.EidConfiguration();
    TimerTypeCertRenewal timerTypeCertRenewal = new TimerTypeCertRenewal(42, TimerUnit.HOURS, 20);
    TimerType timerType = new TimerType(36, TimerUnit.HOURS);
    TimerConfigurationType timerConfigurationType = new TimerConfigurationType(timerTypeCertRenewal, timerType,
                                                                               timerType, timerType,
                                                                               new EntanglementTimerType(1,
                                                                                                         TimerUnit.HOURS,
                                                                                                         true),
                                                                               null, null);
    eidConfiguration.setTimerConfiguration(timerConfigurationType);
    eidasMiddlewareConfig.setEidConfiguration(eidConfiguration);
    return eidasMiddlewareConfig;
  }
}
