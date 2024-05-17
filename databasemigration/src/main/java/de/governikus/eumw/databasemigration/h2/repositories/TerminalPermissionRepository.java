package de.governikus.eumw.databasemigration.h2.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasemigration.entities.TerminalPermission;


@Repository
public interface TerminalPermissionRepository extends JpaRepository<TerminalPermission, String>
{

  public Optional<TerminalPermission> findByPendingRequest_MessageID(String messageID);
}
