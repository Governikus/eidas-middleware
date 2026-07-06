package de.governikus.eumw.databasecleanup.hsql.secondary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.TimerHistory;


/**
 * Repository for Entity {@link TimerHistory}
 *
 * @author tca
 */
@Repository
public interface SecondaryTimerHistoryRepository extends JpaRepository<TimerHistory, Long>
{

}
