package de.governikus.eumw.poseidas.server.pki.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.poseidas.server.pki.entities.TimerHistory;


/**
 * Repository for Entity {@link TimerHistory}
 *
 * @author tca
 */
@Repository
public interface TimerHistoryRepository extends JpaRepository<TimerHistory, Long>
{

  List<TimerHistory> findAllByTimerTypeOrderByTimestampAsc(TimerHistory.TimerType timerType);
}
