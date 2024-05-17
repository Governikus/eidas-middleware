package de.governikus.eumw.poseidas.server.pki.repositories;

import de.governikus.eumw.poseidas.server.pki.entities.CertInChain;
import de.governikus.eumw.poseidas.server.pki.entities.CertInChainPK;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertInChainRepository extends JpaRepository<CertInChain, CertInChainPK> {
}
