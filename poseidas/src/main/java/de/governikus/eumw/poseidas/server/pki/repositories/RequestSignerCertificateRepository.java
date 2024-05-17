package de.governikus.eumw.poseidas.server.pki.repositories;

import de.governikus.eumw.poseidas.server.pki.entities.CertInChainPK;
import de.governikus.eumw.poseidas.server.pki.entities.RequestSignerCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RequestSignerCertificateRepository
  extends JpaRepository<RequestSignerCertificate, CertInChainPK>
{}
