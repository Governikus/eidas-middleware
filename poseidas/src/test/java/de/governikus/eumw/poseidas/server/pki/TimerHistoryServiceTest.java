package de.governikus.eumw.poseidas.server.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;
import de.governikus.eumw.poseidas.server.pki.repositories.TimerHistoryRepository;


class TimerHistoryServiceTest
{

  private TimerHistoryRepository timerHistoryRepository;

  private TimerHistoryService timerHistoryService;

  @BeforeEach
  void setUp()
  {
    timerHistoryRepository = Mockito.mock(TimerHistoryRepository.class);
    timerHistoryService = new TimerHistoryService(timerHistoryRepository);
  }

  @Test
  void saveTimer()
  {
    List<TimerHistory> mockList = new ArrayList<>();

    Mockito.when(timerHistoryRepository.findAllByTimerTypeOrderByTimestampAsc(TimerHistory.TimerType.CVC_RENEWAL_TIMER))
           .thenReturn(mockList);

    timerHistoryService.saveTimer(TimerHistory.TimerType.CVC_RENEWAL_TIMER, "MESSAGE", true, true);

    Mockito.verify(timerHistoryRepository, Mockito.times(0)).delete(Mockito.any());

    ArgumentCaptor<TimerHistory> captor = ArgumentCaptor.forClass(TimerHistory.class);
    Mockito.verify(timerHistoryRepository, Mockito.times(1)).save(captor.capture());
    TimerHistory saved = captor.getValue();

    assertEquals(TimerHistory.TimerType.CVC_RENEWAL_TIMER, saved.getTimerType());
    assertEquals("MESSAGE", saved.getMessage());
    assertTrue(saved.isSuccess());
    assertNotNull(saved.getTimestamp());
  }

  @Test
  void saveTimerWith50Entries()
  {
    List<TimerHistory> mockList = new ArrayList<>();
    // Oldest Timer
    Date date = new Date();
    date.setTime(0);
    TimerHistory oldestTimer = new TimerHistory(TimerHistory.TimerType.CVC_RENEWAL_TIMER, "MESSAGE 1", date, true);
    mockList.add(oldestTimer);
    // Remaining 49 Timers
    for ( int i = 2 ; i <= 50 ; i++ )
    {
      mockList.add(new TimerHistory(TimerHistory.TimerType.CVC_RENEWAL_TIMER, "MESSAGE " + i, new Date(), true));
    }

    Mockito.when(timerHistoryRepository.findAllByTimerTypeOrderByTimestampAsc(TimerHistory.TimerType.CVC_RENEWAL_TIMER))
           .thenReturn(mockList);

    timerHistoryService.saveTimer(TimerHistory.TimerType.CVC_RENEWAL_TIMER, "MESSAGE", true, true);

    Mockito.verify(timerHistoryRepository, Mockito.times(1)).delete(oldestTimer);

    ArgumentCaptor<TimerHistory> captor = ArgumentCaptor.forClass(TimerHistory.class);
    Mockito.verify(timerHistoryRepository, Mockito.times(1)).save(captor.capture());

    TimerHistory saved = captor.getValue();

    assertEquals(TimerHistory.TimerType.CVC_RENEWAL_TIMER, saved.getTimerType());
    assertEquals("MESSAGE", saved.getMessage());
    assertTrue(saved.isSuccess());
    assertNotNull(saved.getTimestamp());
  }

  @Test
  void saveTimerWithTimerExecutionFalse()
  {
    timerHistoryService.saveTimer(TimerHistory.TimerType.CVC_RENEWAL_TIMER, "MESSAGE", true, false);
    Mockito.verify(timerHistoryRepository, Mockito.times(0)).delete(Mockito.any());
    Mockito.verify(timerHistoryRepository, Mockito.times(0)).save(Mockito.any());
  }

}
