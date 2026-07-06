package de.governikus.eumw.databasecleanup.migration;

import java.util.List;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import de.governikus.eumw.databasecleanup.entities.TimerHistory;
import de.governikus.eumw.databasecleanup.hsql.primary.CreatePrimaryBackup;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryCVCUpdateLockRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryCertInChainRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryChangeKeyLockRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryConfigurationRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryKeyArchiveRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryPendingCertificateRequestRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryPendingCsrRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryRequestSignerCertificateRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryTerminalPermissionRepository;
import de.governikus.eumw.databasecleanup.hsql.primary.repositories.PrimaryTimerHistoryRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryCVCUpdateLockRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryCertInChainRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryChangeKeyLockRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryConfigurationRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryKeyArchiveRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryPendingCertificateRequestRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryPendingCsrRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryRequestSignerCertificateRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryTerminalPermissionRepository;
import de.governikus.eumw.databasecleanup.hsql.secondary.repositories.SecondaryTimerHistoryRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Optimizes a eIDAS Middleware HSQL database
 */
@RequiredArgsConstructor
@Component
@Slf4j
public class DatabaseCleanup
{

  private final PrimaryCertInChainRepository primaryCertInChainRepository;

  private final PrimaryChangeKeyLockRepository primaryChangeKeyLockRepository;

  private final PrimaryConfigurationRepository primaryConfigurationRepository;

  private final PrimaryCVCUpdateLockRepository primaryCVCUpdateLockRepository;

  private final PrimaryKeyArchiveRepository primaryKeyArchiveRepository;

  private final PrimaryPendingCertificateRequestRepository primaryPendingCertificateRequestRepository;

  private final PrimaryPendingCsrRepository primaryPendingCsrRepository;

  private final PrimaryRequestSignerCertificateRepository primaryRequestSignerCertificateRepository;

  private final PrimaryTerminalPermissionRepository primaryTerminalPermissionRepository;

  private final PrimaryTimerHistoryRepository primaryTimerHistoryRepository;

  private final SecondaryCertInChainRepository secondaryCertInChainRepository;

  private final SecondaryChangeKeyLockRepository secondaryChangeKeyLockRepository;

  private final SecondaryConfigurationRepository secondaryConfigurationRepository;

  private final SecondaryCVCUpdateLockRepository secondaryCVCUpdateLockRepository;

  private final SecondaryKeyArchiveRepository secondaryKeyArchiveRepository;

  private final SecondaryPendingCertificateRequestRepository secondaryPendingCertificateRequestRepository;

  private final SecondaryPendingCsrRepository secondaryPendingCsrRepository;

  private final SecondaryRequestSignerCertificateRepository secondaryRequestSignerCertificateRepository;

  private final SecondaryTerminalPermissionRepository secondaryTerminalPermissionRepository;

  private final SecondaryTimerHistoryRepository secondaryTimerHistoryRepository;

  private final DatabaseManagement databaseManagement;

  private final CreatePrimaryBackup createPrimaryBackup;

  /**
   * Moves all entities from the current database to an optimized one, stops the databases in a way that all files are
   * optimized and overwrites the old database with the optimized one.
   */
  @EventListener(ApplicationReadyEvent.class)
  public void migrate()
  {
    createPrimaryBackup.backup();

    log.info("Moving ChangeKeyLockRepository");
    secondaryChangeKeyLockRepository.saveAllAndFlush(primaryChangeKeyLockRepository.findAll());

    log.info("Moving ConfigurationRepositor");
    secondaryConfigurationRepository.saveAllAndFlush(primaryConfigurationRepository.findAll());

    log.info("Moving CVCUpdateLockRepository");
    secondaryCVCUpdateLockRepository.saveAllAndFlush(primaryCVCUpdateLockRepository.findAll());

    log.info("Moving KeyArchiveRepository");
    secondaryKeyArchiveRepository.saveAllAndFlush(primaryKeyArchiveRepository.findAll());

    log.info("Moving PendingCertificateRequestRepository");
    secondaryPendingCertificateRequestRepository.saveAllAndFlush(primaryPendingCertificateRequestRepository.findAll());

    log.info("Moving PendingCsrRepository");
    secondaryPendingCsrRepository.saveAllAndFlush(primaryPendingCsrRepository.findAll());

    log.info("Moving RequestSignerCertificateRepository");
    secondaryRequestSignerCertificateRepository.saveAllAndFlush(primaryRequestSignerCertificateRepository.findAll());

    log.info("Moving TerminalPermissionRepository");
    secondaryTerminalPermissionRepository.saveAllAndFlush(primaryTerminalPermissionRepository.findAll());

    log.info("Moving CertInChainRepository");
    secondaryCertInChainRepository.saveAllAndFlush(primaryCertInChainRepository.findAll());

    log.info("Moving TimerHistoryRepository");

    // Must be migrated sequentially because of the auto generated id
    List<TimerHistory> timerHistories = primaryTimerHistoryRepository.findAll();
    for ( TimerHistory timerHistory : timerHistories )
    {
      secondaryTimerHistoryRepository.saveAndFlush(new TimerHistory(timerHistory.getTimerType(),
                                                                    timerHistory.getMessage(),
                                                                    timerHistory.getTimestamp(),
                                                                    timerHistory.isSuccess()));
    }

    log.info("Successfully created clean up database copy");

    log.info("Stopping databases");
    databaseManagement.shutdownPrimary();
    databaseManagement.shutdownSecondary();

    log.info("Overwriting old database with cleaned one");
    databaseManagement.makeSecondaryPrimary();
  }
}
