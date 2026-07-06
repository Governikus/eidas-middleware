package de.governikus.eumw.databasecleanup.hsql.secondary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.CertInChainPK;
import de.governikus.eumw.databasecleanup.entities.RequestSignerCertificate;


@Repository
public interface SecondaryRequestSignerCertificateRepository
  extends JpaRepository<RequestSignerCertificate, CertInChainPK>
{}
