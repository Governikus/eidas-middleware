package de.governikus.eumw.databasemigration.hsql.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasemigration.entities.ChangeKeyLock;


@Repository
public interface HsqlChangeKeyLockRepository extends JpaRepository<ChangeKeyLock, String>
{

  public List<ChangeKeyLock> getAllByAutentIP(String autentIP);

  public List<ChangeKeyLock> getAllByAutentIPNot(String autentIP);
}
