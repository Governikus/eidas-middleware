package de.governikus.eumw.databasemigration.migration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Sort;

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


/**
 * Test the migration by comparing the old and new repositories
 */
@SpringBootTest
class DatabaseMigratorTest
{

  // H2 repositories
  @Autowired
  private ChangeKeyLockRepository changeKeyLockRepository;

  @Autowired
  private ConfigurationRepository configurationRepository;

  @Autowired
  private CVCUpdateLockRepository cvcUpdateLockRepository;

  @Autowired
  private KeyArchiveRepository keyArchiveRepository;

  @Autowired
  private TerminalPermissionRepository terminalPermissionRepository;

  // Hsql repositories
  @Autowired
  private HsqlChangeKeyLockRepository hsqlChangeKeyLockRepository;

  @Autowired
  private HsqlConfigurationRepository hsqlConfigurationRepository;

  @Autowired
  private HsqlCVCUpdateLockRepository hsqlCVCUpdateLockRepository;

  @Autowired
  private HsqlKeyArchiveRepository hsqlKeyArchiveRepository;

  @Autowired
  private HsqlTerminalPermissionRepository hsqlTerminalPermissionRepository;

  @Test
  void testMigration()
  {
    Assertions.assertIterableEquals(changeKeyLockRepository.findAll(), hsqlChangeKeyLockRepository.findAll());
    Assertions.assertIterableEquals(configurationRepository.findAll(), hsqlConfigurationRepository.findAll());
    Assertions.assertIterableEquals(cvcUpdateLockRepository.findAll(), hsqlCVCUpdateLockRepository.findAll());
    Assertions.assertIterableEquals(keyArchiveRepository.findAll(Sort.by(Sort.Direction.ASC, "keyName")),
                                    hsqlKeyArchiveRepository.findAll());
    Assertions.assertIterableEquals(terminalPermissionRepository.findAll(Sort.by(Sort.Direction.ASC, "refID")),
                                    hsqlTerminalPermissionRepository.findAll());
  }
}
