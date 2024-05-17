package de.governikus.eumw.databasemigration.migration;

import org.springframework.stereotype.Service;

import de.governikus.eumw.databasemigration.h2.repositories.CVCUpdateLockRepository;
import de.governikus.eumw.databasemigration.h2.repositories.ChangeKeyLockRepository;
import de.governikus.eumw.databasemigration.h2.repositories.ConfigurationRepository;
import de.governikus.eumw.databasemigration.h2.repositories.KeyArchiveRepository;
import de.governikus.eumw.databasemigration.h2.repositories.TerminalPermissionRepository;
import de.governikus.eumw.databasemigration.hsql.repositories.HsqlCVCUpdateLockRepository;
import de.governikus.eumw.databasemigration.hsql.repositories.HsqlChangeKeyLockRepository;
import de.governikus.eumw.databasemigration.hsql.repositories.HsqlConfigurationRepository;
import de.governikus.eumw.databasemigration.hsql.repositories.HsqlKeyArchiveRepository;
import de.governikus.eumw.databasemigration.hsql.repositories.HsqlTerminalPermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * Migrate all entries except for the block list from the old H2 database to the new HSQL database
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DatabaseMigrator
{

  // H2 repositories
  private final ChangeKeyLockRepository changeKeyLockRepository;

  private final ConfigurationRepository configurationRepository;

  private final CVCUpdateLockRepository cvcUpdateLockRepository;

  private final KeyArchiveRepository keyArchiveRepository;

  private final TerminalPermissionRepository terminalPermissionRepository;

  // Hsql repositories
  private final HsqlChangeKeyLockRepository hsqlChangeKeyLockRepository;

  private final HsqlConfigurationRepository hsqlConfigurationRepository;

  private final HsqlCVCUpdateLockRepository hsqlCVCUpdateLockRepository;

  private final HsqlKeyArchiveRepository hsqlKeyArchiveRepository;

  private final HsqlTerminalPermissionRepository hsqlTerminalPermissionRepository;


  public void migrate()
  {
    log.info("Number of terminals: {}", terminalPermissionRepository.count());

    migrateLocks();
    migrateKeyArchive();
    migrateTerminals();
    migrateConfiguration();

    log.info("Successfully finished the migration.");
  }

  private void migrateLocks()
  {
    hsqlChangeKeyLockRepository.saveAll(changeKeyLockRepository.findAll());
    hsqlCVCUpdateLockRepository.saveAll(cvcUpdateLockRepository.findAll());
  }

  private void migrateKeyArchive()
  {
    hsqlKeyArchiveRepository.saveAll(keyArchiveRepository.findAll());
  }

  private void migrateTerminals()
  {
    hsqlTerminalPermissionRepository.saveAll(terminalPermissionRepository.findAll());
  }

  private void migrateConfiguration()
  {
    hsqlConfigurationRepository.saveAll(configurationRepository.findAll());
  }

}
