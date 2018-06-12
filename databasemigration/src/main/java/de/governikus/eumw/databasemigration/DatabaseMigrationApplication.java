/*
 * Copyright (c) 2018 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.databasemigration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.Banner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import lombok.extern.slf4j.Slf4j;


/**
 * The main application class to perform the database migration of the eIDAS Middleware database to version
 * 1.0.3.
 */
@SpringBootApplication
@Slf4j
public class DatabaseMigrationApplication implements CommandLineRunner
{

  /**
   * the datasource url from the application.properties
   */
  @Value("${spring.datasource.url}")
  private String datasourceURL;

  /**
   * The high level abstraction of the database connection
   */
  @Autowired
  DatabaseConnector connector;

  public static void main(String[] args)
  {
    // disabled banner, don't want to see the spring logo
    SpringApplication app = new SpringApplication(DatabaseMigrationApplication.class);
    app.setBannerMode(Banner.Mode.OFF);
    app.run(args);
  }

  @Override
  public void run(String... strings)
  {
    log.info("Running the database migration for 1.0.1 and 1.0.2 to 1.0.3.");
    log.info("Using datasource URL: {}", datasourceURL);

    // Check that there is only one terminal in the database
    if (connector.getTerminalsFromTerminalpermission().size() != 1)
    {
      log.error("There are more than one service providers in the database available.");
      log.error("Please contact Governikus with this log.");
      System.exit(1);
    }

    boolean migrationSuccessful;

    // Check if the blacklist data can be migrated
    if (connector.checkPrimaryKey())
    {
      // remove outdated SectorIDs from Blacklistentry before migrating
      connector.removeOutdatedSectorIDsFromBlacklistentry();

      // remove outdated BlacklistIDs from Blacklistentry before migrating
      connector.removeOutdatedVersionsFromBlacklistentry();

      // perform the migration
      migrationSuccessful = connector.performMigrationWithData();
    }
    else
    {
      log.info("The blacklist data will be deleted. Update the blacklist using the web administration interface afterwards.");
      migrationSuccessful = connector.performMigrationWithoutData();
    }

    if (migrationSuccessful)
    {
      log.info("Successfully migrated the database.");
    }
    else
    {
      log.error("Something went wrong during the migration.");
      log.error("Please contact Governikus with this log.");
    }
  }

}
