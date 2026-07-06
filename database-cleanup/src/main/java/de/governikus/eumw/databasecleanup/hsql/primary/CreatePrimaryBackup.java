package de.governikus.eumw.databasecleanup.hsql.primary;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import de.governikus.eumw.databasecleanup.hsql.primary.configuration.HsqlPrimaryDatabaseConfig;

import lombok.extern.slf4j.Slf4j;


/**
 * Creates a backup of the primary database
 */
@Component
@Slf4j
public class CreatePrimaryBackup
{

  @PersistenceContext(unitName = HsqlPrimaryDatabaseConfig.HSQL_ENTITY_MANAGER_FACTORY)
  private EntityManager primaryEntityManager;

  /**
   * Creates a backup of the primary database
   */
  @Transactional(transactionManager = HsqlPrimaryDatabaseConfig.HSQL_TRANSACTION_MANAGER)
  public void backup()
  {
    String absolutePath = new File("database-backup-" + LocalDateTime.now()
                                                                     .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                                                                     .replace(":", "-")).getAbsolutePath();
    log.info("Creating database backup at {}", absolutePath);
    primaryEntityManager.createNativeQuery("BACKUP DATABASE TO '%s/' BLOCKING AS FILES".formatted(absolutePath))
                        .executeUpdate();
    log.info("Database backup created at {} completed", absolutePath);

    if (Files.notExists(Path.of(absolutePath)))
    {
      throw new IllegalStateException("Database backup at " + absolutePath + " does not exist");
    }
  }
}
