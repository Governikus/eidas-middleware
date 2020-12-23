package de.governikus.eumw.poseidas.server.pki;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertInChainRepository extends JpaRepository<CertInChain,CertInChainPK> {
}
