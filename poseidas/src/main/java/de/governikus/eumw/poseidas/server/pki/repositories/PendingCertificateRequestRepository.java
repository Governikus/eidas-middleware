package de.governikus.eumw.poseidas.server.pki.repositories;

import de.governikus.eumw.poseidas.server.pki.entities.PendingCertificateRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface PendingCertificateRequestRepository extends JpaRepository<PendingCertificateRequest, String>
{

}
