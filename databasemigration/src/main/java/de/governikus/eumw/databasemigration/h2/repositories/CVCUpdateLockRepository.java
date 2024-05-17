package de.governikus.eumw.databasemigration.h2.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasemigration.entities.CVCUpdateLock;


@Repository
public interface CVCUpdateLockRepository extends JpaRepository<CVCUpdateLock, String>
{}
