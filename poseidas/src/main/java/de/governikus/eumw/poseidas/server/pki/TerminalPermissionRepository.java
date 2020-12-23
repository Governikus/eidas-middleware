package de.governikus.eumw.poseidas.server.pki;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface TerminalPermissionRepository extends JpaRepository<TerminalPermission, String>
{

  public Optional<TerminalPermission> findByPendingRequest_MessageID(String messageID);
}
