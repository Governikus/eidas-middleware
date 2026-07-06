package de.governikus.eumw.databasecleanup.hsql.secondary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.PendingCertificateRequest;


@Repository
public interface SecondaryPendingCertificateRequestRepository extends JpaRepository<PendingCertificateRequest, String>
{

}
