/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.databasemigration;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import java.nio.charset.StandardCharsets;
import java.sql.ResultSetMetaData;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import lombok.extern.slf4j.Slf4j;


/**
 * Test class to check database related methods.
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {DatabaseConnector.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
@Slf4j
@DataJpaTest
public class DatabaseConnectorTest
{

  /**
   * Access to the database
   */
  @Autowired
  JdbcTemplate jdbcTemplate;

  /**
   * system under test
   */
  @Autowired
  DatabaseConnector connector;

  /**
   * Check that the migration was successful.
   */
  @Test
  public void testMigration()
  {
    // Check that the primary key is correct
    assertThat("Primary key should be correct", connector.checkPrimaryKey(), is(true));

    // perform the migration
    assertThat("Migration is successful", connector.performMigrationWithData(), is(true));

    checkSchemaChanges();

    // check that the value from the old columns is copied
    long blacklistversion = jdbcTemplate.queryForObject("SELECT BLACKLISTVERSION FROM TERMINALPERMISSION WHERE REFID = ?",
                                                        Long.TYPE,
                                                        "test");
    assertThat("The old value must be copied", blacklistversion, is(1337L));

    // Check that the primary key is correct
    assertThat("Primary key should be correct", connector.checkPrimaryKey(), is(true));
  }

  private void checkSchemaChanges()
  {
    // check that the column in BLACKLISTENTRY is deleted
    List<String> columnsInBlacklistentry = getColumnsFromTable("SELECT * FROM BLACKLISTENTRY");
    assertThat("Only SECTORID and SPECIFICID must be present",
               columnsInBlacklistentry,
               Matchers.containsInAnyOrder("SECTORID", "SPECIFICID"));

    // check that the column in TERMINALPERMISSION is added
    List<String> columnsInTerminalpermission = getColumnsFromTable("SELECT * FROM TERMINALPERMISSION");
    assertThat("ONLY REFID, SECTORID and BLACKLISTVERSION must be present",
               columnsInTerminalpermission,
               Matchers.containsInAnyOrder("REFID", "SECTORID", "BLACKLISTVERSION"));
  }

  private List<String> getColumnsFromTable(String query)
  {
    return jdbcTemplate.query(query, resultSet -> {
      ResultSetMetaData rsmd = resultSet.getMetaData();
      ArrayList<String> result = new ArrayList<>();
      for ( int i = 1 ; i < rsmd.getColumnCount() + 1 ; i++ )
      {
        result.add(rsmd.getColumnName(i));
      }
      return result;
    });
  }

  /**
   * Check that only outdated SectorIDs are removed and nothing more. Also check that all outdated SectorIDs
   * are removed.
   */
  @Test
  public void testRemoveOutdatedSectorIDs()
  {
    assertThat("The initial database must contain 5 entries", getNumberOfRows(), is(5));
    connector.removeOutdatedSectorIDsFromBlacklistentry();
    assertThat("No entry should be deleted", getNumberOfRows(), is(5));

    // Add 10 outdated SectorIDs
    for ( int i = 0 ; i < 10 ; i++ )
    {
      addEntryToBlacklistentry(Base64.getEncoder().encodeToString("XXX".getBytes(StandardCharsets.UTF_8)),
                               UUID.randomUUID().toString(),
                               "1338");
    }

    assertThat("There should be 15 entries", getNumberOfRows(), is(15));
    assertThat("There should be two different SectorIDs", getUniqueSectorIDs().size(), is(2));

    // Remove outdated SectorIDs
    connector.removeOutdatedSectorIDsFromBlacklistentry();
    assertThat("The 10 unused entries should be deleted", getNumberOfRows(), is(5));
    assertThat("There should be only the original SectorID",
               getUniqueSectorIDs(),
               Matchers.containsInAnyOrder(Base64.getEncoder()
                                                 .encodeToString("AAA".getBytes(StandardCharsets.UTF_8))));
  }

  private int getNumberOfRows()
  {
    return jdbcTemplate.queryForObject("SELECT COUNT(*) FROM BLACKLISTENTRY", Integer.class);
  }

  private void addEntryToBlacklistentry(String sectorID, String specificID, String blacklistVersion)
  {
    jdbcTemplate.update("INSERT INTO BLACKLISTENTRY (SECTORID, SPECIFICID, BLACKLISTVERSION) VALUES (?,?,?)",
                        sectorID,
                        specificID,
                        blacklistVersion);
  }

  private List<String> getUniqueSectorIDs()
  {
    return jdbcTemplate.queryForList("SELECT DISTINCT SECTORID FROM BLACKLISTENTRY", String.class);
  }

  /**
   * Check that only outdated blacklist versions are removed and nothing more. Also check that all outdated
   * blacklist versions are removed.
   */
  @Test
  public void testRemoveOutdatedBlacklistVersions()
  {
    assertThat("The initial database must contain 5 entries", getNumberOfRows(), is(5));

    // cleanup should not delete any entries as they are all the same version
    connector.removeOutdatedVersionsFromBlacklistentry();
    assertThat("No current versions should be deleted", getNumberOfRows(), is(5));

    // Add entries with older blacklist version
    for ( int i = 0 ; i < 10 ; i++ )
    {
      addEntryToBlacklistentry(Base64.getEncoder().encodeToString("XXX".getBytes(StandardCharsets.UTF_8)),
                               UUID.randomUUID().toString(),
                               "1000");
    }
    assertThat("There must be 15 entries", getNumberOfRows(), is(15));

    // Perform the clean up
    connector.removeOutdatedVersionsFromBlacklistentry();
    assertThat("The 10 outdated entries should be deleted", getNumberOfRows(), is(5));
    List<Long> expected = Arrays.asList(1337L);
    assertThat("Only the recent blacklist version should be present",
               getUniqueBlacklistVersions(),
               Matchers.containsInAnyOrder(expected.toArray()));
  }

  private List<Long> getUniqueBlacklistVersions()
  {
    return jdbcTemplate.queryForList("SELECT DISTINCT (BLACKLISTVERSION) FROM BLACKLISTENTRY", Long.TYPE);
  }

  /**
   * Check the case that the primary key contains all three columns.
   */
  @Test
  public void testFalsePrimaryKey()
  {
    jdbcTemplate.update("ALTER TABLE BLACKLISTENTRY DROP PRIMARY KEY");
    jdbcTemplate.update("ALTER TABLE BLACKLISTENTRY ADD PRIMARY KEY (SECTORID,SPECIFICID,BLACKLISTVERSION)");

    assertThat("Primary key should be corrupted", connector.checkPrimaryKey(), is(false));
    connector.performMigrationWithoutData();

    checkSchemaChanges();

    // Check that the value for the BLACKLISTVERSION is null
    Long blacklistversion = jdbcTemplate.queryForObject("SELECT BLACKLISTVERSION FROM TERMINALPERMISSION WHERE REFID = ?",
                                                        Long.TYPE,
                                                        "test");
    assertThat("The old value must be copied", blacklistversion, nullValue());

    // Check that the primary key is correct
    assertThat("Primary key must be correct", connector.checkPrimaryKey(), is(true));
  }
}
