package de.governikus.eumw.databasemigration.hsql.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasemigration.entities.TerminalPermission;


@Repository
public interface HsqlTerminalPermissionRepository extends JpaRepository<TerminalPermission, String>
{

  public Optional<TerminalPermission> findByPendingRequest_MessageID(String messageID);
}
