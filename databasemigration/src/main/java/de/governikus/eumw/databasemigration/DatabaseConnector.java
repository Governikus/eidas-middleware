/*
 * Copyright (c) 2020 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.databasemigration;

import java.sql.ResultSetMetaData;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.rowset.SqlRowSet;
import org.springframework.stereotype.Repository;

import lombok.extern.slf4j.Slf4j;


/**
 * This class serves for high level abstraction of the database.
 */
@Repository
@Slf4j
public class DatabaseConnector
{

  /**
   * Access to the database
   */
  private final JdbcTemplate jdbcTemplate;

  /**
   * Default constructor with dependency injection
   *
   * @param jdbcTemplate Used to access the database
   */
  public DatabaseConnector(JdbcTemplate jdbcTemplate)
  {
    this.jdbcTemplate = jdbcTemplate;
  }

  /**
   * Return the list of terminals from the TERMINALPERMISSION table
   */
  public List<byte[]> getTerminalsFromTerminalpermission()
  {
    return jdbcTemplate.queryForList("SELECT SECTORID FROM TERMINALPERMISSION", byte[].class);
  }

  /**
   * Remove entries from the BLACKLISTENTRY table that contain an outdated SectorID.
   */
  public void removeOutdatedSectorIDsFromBlacklistentry()
  {
    int rowsAffected = jdbcTemplate.update("DELETE FROM BLACKLISTENTRY WHERE SECTORID <> ?",
                                           Base64.getEncoder()
                                                 .encodeToString(getTerminalsFromTerminalpermission().get(0)));
    log.info("Deleted {} entries with outdated sectorIDs from Blacklistentry", rowsAffected);
  }

  /**
   * Remove entries from the BLACKLISTENTRY table that contain an outdated BlackListVersion.
   */
  public void removeOutdatedVersionsFromBlacklistentry()
  {
    List<Long> blacklistversions = jdbcTemplate.queryForList("SELECT DISTINCT BLACKLISTVERSION FROM BLACKLISTENTRY",
                                                             Long.TYPE);
    if (blacklistversions.size() > 1)
    {
      Long currentBlacklistversion = Collections.max(blacklistversions);
      int rowsAffected = jdbcTemplate.update("DELETE FROM BLACKLISTENTRY WHERE BLACKLISTVERSION <> ?",
                                             currentBlacklistversion);
      log.info("Deleted {} entries with outdated Blacklist versions from Blacklistentry", rowsAffected);
    }
    else
    {
      log.info("No entries with outdated Blacklist versions found.");
    }
  }

  /**
   * Check that only SECTORID and SPECIFICID are used for the primary key
   *
   * @return true if only SECTORID and SPECIFICID are used for the primary key
   */
  public boolean checkPrimaryKey()
  {
    SqlRowSet result = jdbcTemplate.queryForRowSet("SELECT * FROM INFORMATION_SCHEMA.CONSTRAINTS WHERE TABLE_NAME = 'BLACKLISTENTRY'");
    if (!result.next())
    {
      return false;
    }

    boolean correctPrimaryKey = "SECTORID,SPECIFICID".equals(result.getString("COLUMN_LIST"));

    // There must be only one constraint on this table
    if (result.next())
    {
      correctPrimaryKey = false;
    }

    return correctPrimaryKey;
  }

  /**
   * Truncate BLACKLISTENTRY. Delete the column BLACKLISTVERSION from BLACKLISTENTRY, create the column
   * BLACKLISTVERSION in TERMINALPERMISSION. This must only be used if there is only one terminal available.
   */
  public boolean performMigrationWithoutData()
  {
    jdbcTemplate.update("TRUNCATE TABLE BLACKLISTENTRY");
    jdbcTemplate.update("ALTER TABLE BLACKLISTENTRY DROP PRIMARY KEY");
    jdbcTemplate.update("ALTER TABLE BLACKLISTENTRY ADD PRIMARY KEY (SECTORID,SPECIFICID)");
    jdbcTemplate.update("ALTER TABLE BLACKLISTENTRY DROP COLUMN BLACKLISTVERSION");
    jdbcTemplate.update("ALTER TABLE TERMINALPERMISSION ADD BLACKLISTVERSION BIGINT;");
    int columnCount = getColumnCountForBlacklistentry();
    return columnCount == 2;
  }

  /**
   * Delete the column BLACKLISTVERSION from BLACKLISTENTRY, create the column BLACKLISTVERSION in
   * TERMINALPERMISSION. Copy if available the newest value of BLACKLISTVERSION from BLACKLISTENTRY to
   * TERMINALPERMISSION. This must only be used if there is only one terminal available.
   */
  public boolean performMigrationWithData()
  {
    jdbcTemplate.update("ALTER TABLE TERMINALPERMISSION ADD BLACKLISTVERSION BIGINT;");
    List<Long> blacklistversions = jdbcTemplate.queryForList("SELECT DISTINCT BLACKLISTVERSION FROM BLACKLISTENTRY",
                                                             Long.TYPE);
    Long blacklistversion;
    if (blacklistversions.size() > 1)
    {
      blacklistversion = Collections.max(blacklistversions);
    }
    else if (blacklistversions.size() == 1)
    {
      blacklistversion = blacklistversions.get(0);
    }
    else
    {
      blacklistversion = null;
    }
    jdbcTemplate.update("UPDATE TERMINALPERMISSION SET BLACKLISTVERSION = ?", blacklistversion);
    jdbcTemplate.update("ALTER TABLE BLACKLISTENTRY DROP COLUMN BLACKLISTVERSION");
    int columnCount = getColumnCountForBlacklistentry();
    return columnCount == 2;
  }

  private int getColumnCountForBlacklistentry()
  {
    return jdbcTemplate.query("SELECT * FROM BLACKLISTENTRY", resultSet -> {
      ResultSetMetaData rsmd = resultSet.getMetaData();
      return rsmd.getColumnCount();
    });
  }

}
