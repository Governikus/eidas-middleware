package de.governikus.eumw.databasecleanup.hsql.primary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.CVCUpdateLock;


@Repository
public interface PrimaryCVCUpdateLockRepository extends JpaRepository<CVCUpdateLock, String>
{}
