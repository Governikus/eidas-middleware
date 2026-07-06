package de.governikus.eumw.databasecleanup.hsql.primary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.ChangeKeyLock;


@Repository
public interface PrimaryChangeKeyLockRepository extends JpaRepository<ChangeKeyLock, String>
{

}
