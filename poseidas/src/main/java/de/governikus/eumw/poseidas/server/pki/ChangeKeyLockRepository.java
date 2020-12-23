package de.governikus.eumw.poseidas.server.pki;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface ChangeKeyLockRepository extends JpaRepository<ChangeKeyLock, String>
{

  public List<ChangeKeyLock> getAllByAutentIP(String autentIP);

  public List<ChangeKeyLock> getAllByAutentIPNot(String autentIP);
}
