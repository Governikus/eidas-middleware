package de.governikus.eumw.databasecleanup.hsql.primary.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import de.governikus.eumw.databasecleanup.entities.CertInChain;
import de.governikus.eumw.databasecleanup.entities.CertInChainPK;


@Repository
public interface PrimaryCertInChainRepository extends JpaRepository<CertInChain, CertInChainPK>
{}
