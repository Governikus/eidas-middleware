package de.governikus.eumw.eidasmiddleware.projectconfig.database;

import java.sql.ResultSet;
import java.util.Optional;

import jakarta.annotation.PostConstruct;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.StatementCallback;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * This class drops a constraint in the HSQL database. The check prohibits timer history types that are not explicitly
 * allowed from been persisted. Since hibernate does not update this constraint after expanding the enum, we must remove
 * this check.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TimerHistoryConstraintDropper
{

  private final JdbcTemplate jdbcTemplate;

  @PostConstruct
  public void init()
  {

    String constraintName;
    try
    {
      Optional<String> optionalConstraintName = Optional.ofNullable(jdbcTemplate.execute((StatementCallback<String>)stmt -> {
        stmt.execute("""
          SELECT cc.CONSTRAINT_NAME
                     FROM information_schema.check_constraints cc
                     WHERE cc.CONSTRAINT_SCHEMA = 'PUBLIC'
                       AND cc.CHECK_CLAUSE LIKE '(PUBLIC.TIMERHISTORY.TIMERTYPE) IN %' LIMIT 1;
          """);
        ResultSet resultSet = stmt.getResultSet();

        if (!resultSet.next())
        {
          log.debug("No constraints found - nothing to drop");
          return null;
        }

        return resultSet.getString(1);
      }));

      if (optionalConstraintName.isEmpty())
      {
        log.debug("No constraints name found - nothing to drop");
        return;
      }

      constraintName = optionalConstraintName.get();
    }
    catch (Exception e) // We catch every exception to be as resilient as possible
    {
      log.warn("Could not check for constraints on timer history table", e);
      return;
    }

    try
    {
      log.trace("Dropping timer history constraint {}", constraintName);
      jdbcTemplate.execute("ALTER TABLE TIMERHISTORY DROP CONSTRAINT %s".formatted(constraintName));
      log.info("Dropped timer history constraint {}", constraintName);
    }
    catch (Exception e) // We catch every exception to be as resilient as possible
    {
      log.warn("Could not drop timer history constraint", e);
    }

  }

}
