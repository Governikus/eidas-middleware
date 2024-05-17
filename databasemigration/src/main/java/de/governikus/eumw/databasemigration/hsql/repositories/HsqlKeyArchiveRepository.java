package de.governikus.eumw.databasemigration.hsql.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasemigration.entities.KeyArchive;


@Repository
public interface HsqlKeyArchiveRepository extends JpaRepository<KeyArchive, String>
{

}
