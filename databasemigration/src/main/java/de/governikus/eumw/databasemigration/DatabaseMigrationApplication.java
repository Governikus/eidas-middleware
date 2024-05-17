/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by the
 * European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except in compliance
 * with the Licence. You may obtain a copy of the Licence at: http://joinup.ec.europa.eu/software/page/eupl Unless
 * required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an
 * "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the
 * specific language governing permissions and limitations under the Licence.
 */

package de.governikus.eumw.databasemigration;

import org.springframework.boot.Banner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import de.governikus.eumw.databasemigration.migration.DatabaseMigrator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * The main application class to perform the database migration of the eIDAS Middleware database
 */
@SpringBootApplication
@Slf4j
@RequiredArgsConstructor
public class DatabaseMigrationApplication implements CommandLineRunner
{

  private final DatabaseMigrator databaseMigrator;

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
    log.info("Running the database migration for EUMW version 3.3.0.");
    databaseMigrator.migrate();
  }

}
