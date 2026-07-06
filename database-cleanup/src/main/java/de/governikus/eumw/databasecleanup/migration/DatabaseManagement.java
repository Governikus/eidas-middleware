package de.governikus.eumw.databasecleanup.migration;

import java.io.File;
import java.util.regex.Pattern;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.hsqldb.DatabaseURL;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import de.governikus.eumw.databasecleanup.hsql.primary.configuration.HsqlPrimaryDatabaseConfig;
import de.governikus.eumw.databasecleanup.hsql.secondary.configuration.HsqlSecondaryDatabaseConfig;

import lombok.extern.slf4j.Slf4j;


/**
 * Allows to shut down a hsql database with a native command or overwrite the database
 */
@Component
@Slf4j
public class DatabaseManagement
{

  @Value("${spring.datasource.url}")
  String databaseUrl;

  @PersistenceContext(unitName = HsqlPrimaryDatabaseConfig.HSQL_ENTITY_MANAGER_FACTORY)
  private EntityManager primaryEntityManager;


  @PersistenceContext(unitName = HsqlSecondaryDatabaseConfig.HSQL_ENTITY_MANAGER_FACTORY)
  private EntityManager secondaryEntityManager;


  /**
   * Sends a native shutdown command to the primary database
   */
  @Transactional(transactionManager = HsqlPrimaryDatabaseConfig.HSQL_TRANSACTION_MANAGER)
  public void shutdownPrimary()
  {
    log.info("Stopping primary database");
    primaryEntityManager.createNativeQuery("SHUTDOWN COMPACT;").executeUpdate();
    log.info("Stopped primary database");
  }

  /**
   * Sends a native shutdown command to the secondary database
   */
  @Transactional(transactionManager = HsqlSecondaryDatabaseConfig.HSQL_TRANSACTION_MANAGER)
  public void shutdownSecondary()
  {
    log.info("Stopping primary database");
    secondaryEntityManager.createNativeQuery("SHUTDOWN COMPACT;").executeUpdate();
    log.info("Stopped primary database");
  }

  /**
   * Overwrites the primary database with the secondary database
   */
  public void makeSecondaryPrimary()
  {
    log.info("Making secondary primary database");
    String primaryPath = DatabaseURL.parseURL(databaseUrl, true, false).getProperty(DatabaseURL.url_database);

    String databaseFolderPath = new File(primaryPath).getParent();
    File databaseFolder = new File(databaseFolderPath);


    Pattern cleanedFilePattern = Pattern.compile(".*" + HsqlSecondaryDatabaseConfig.CLEANED_DB_SUFFIX + "\\.\\w+$");

    // Remove files without clean suffix
    for ( File file : databaseFolder.listFiles() )
    {
      if (cleanedFilePattern.matcher(file.getName()).matches())
      {
        continue;
      }
      log.info("Deleting old database file: {}", file);
      boolean fileDeletionSuccessful = file.delete();
      log.info("Deleting file {} was {}}", file, fileDeletionSuccessful ? "successful" : "unsuccessful");

    }

    // Rename files and remove suffix

    for ( File file : databaseFolder.listFiles() )
    {
      if (!cleanedFilePattern.matcher(file.getAbsolutePath()).matches())
      {
        log.warn("Found file without new database suffix that should have been deleted before: {}", file);
        continue;
      }
      String newPath = file.getAbsolutePath().replace(HsqlSecondaryDatabaseConfig.CLEANED_DB_SUFFIX, "");
      log.info("Renaming new database file: {} to {}", file, newPath);
      boolean fileRenameSuccessful = file.renameTo(new File(newPath));
      log.info("Renaming file {} was {}}", file, fileRenameSuccessful ? "successful" : "unsuccessful");

    }

  }
}
