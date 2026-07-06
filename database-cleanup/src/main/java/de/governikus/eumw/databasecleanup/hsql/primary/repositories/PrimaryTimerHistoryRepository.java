package de.governikus.eumw.databasecleanup.hsql.primary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.TimerHistory;


/**
 * Repository for Entity {@link TimerHistory}
 *
 * @author tca
 */
@Repository
public interface PrimaryTimerHistoryRepository extends JpaRepository<TimerHistory, Long>
{

}
