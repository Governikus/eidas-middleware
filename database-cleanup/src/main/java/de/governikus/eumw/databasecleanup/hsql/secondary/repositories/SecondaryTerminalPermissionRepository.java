package de.governikus.eumw.databasecleanup.hsql.secondary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.TerminalPermission;


@Repository
public interface SecondaryTerminalPermissionRepository extends JpaRepository<TerminalPermission, String>
{

}
