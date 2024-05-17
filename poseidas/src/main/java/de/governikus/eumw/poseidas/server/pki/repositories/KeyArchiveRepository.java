package de.governikus.eumw.poseidas.server.pki.repositories;

import de.governikus.eumw.poseidas.server.pki.entities.KeyArchive;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface KeyArchiveRepository extends JpaRepository<KeyArchive, String>
{

}
