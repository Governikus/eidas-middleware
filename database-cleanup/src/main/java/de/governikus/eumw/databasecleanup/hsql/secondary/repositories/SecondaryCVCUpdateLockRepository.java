package de.governikus.eumw.databasecleanup.hsql.secondary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.CVCUpdateLock;


@Repository
public interface SecondaryCVCUpdateLockRepository extends JpaRepository<CVCUpdateLock, String>
{}
