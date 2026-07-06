package de.governikus.eumw.poseidas.server.database;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import liquibase.change.custom.CustomTaskChange;
import liquibase.database.Database;
import liquibase.database.jvm.JdbcConnection;
import liquibase.exception.CustomChangeException;
import liquibase.exception.DatabaseException;
import liquibase.exception.SetupException;
import liquibase.exception.ValidationErrors;
import liquibase.resource.ResourceAccessor;
import lombok.extern.slf4j.Slf4j;


/**
 * This class is called by liquibase to execute a custom change. The custom change drops an existing constraint on the
 * timer history table. The dropped constraint restricts the possible values for the column holding the timer type.
 */
@Slf4j
public class DropTimerHistroyCheckCustomChange implements CustomTaskChange
{

  @Override
  public void execute(Database database) throws CustomChangeException
  {

    JdbcConnection jdbcConnection = (JdbcConnection)database.getConnection();
    String constraintName;
    try
    {
      Statement statement = jdbcConnection.createStatement();
      statement.execute("""
        SELECT cc.CONSTRAINT_NAME
                   FROM information_schema.check_constraints cc
                   WHERE cc.CONSTRAINT_SCHEMA = 'PUBLIC'
                     AND cc.CHECK_CLAUSE LIKE '(PUBLIC.TIMERHISTORY.TIMERTYPE) IN %' LIMIT 1;
        """);

      ResultSet resultSet = statement.getResultSet();

      if (!resultSet.next())
      {
        throw new CustomChangeException("No constraints found but one expected");
      }

      constraintName = resultSet.getString(1);
      log.debug("Constraint Name: {}", constraintName);
    }
    catch (DatabaseException | SQLException e)
    {
      throw new CustomChangeException("Could not check for constraints on timer history table", e);
    }

    try
    {
      Statement dropStatement = jdbcConnection.createStatement();
      dropStatement.execute("ALTER TABLE TIMERHISTORY DROP CONSTRAINT %s".formatted(constraintName));

    }
    catch (DatabaseException | SQLException e)
    {
      throw new CustomChangeException("Could not drop timer history constraint", e);
    }
  }

  @Override
  public String getConfirmationMessage()
  {
    return "Constraint in timer history table was removed";
  }

  @Override
  public void setUp() throws SetupException
  {
    // Nothing to do
  }

  @Override
  public void setFileOpener(ResourceAccessor resourceAccessor)
  {
    // Nothing to do
  }

  @Override
  public ValidationErrors validate(Database database)
  {
    return null; // NOOP
  }
}
