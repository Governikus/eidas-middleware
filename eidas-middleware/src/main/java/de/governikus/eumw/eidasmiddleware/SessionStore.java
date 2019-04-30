/*
 * Copyright (c) 2019 Governikus KG. Licensed under the EUPL, Version 1.2 or as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work except
 * in compliance with the Licence. You may obtain a copy of the Licence at:
 * http://joinup.ec.europa.eu/software/page/eupl Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package de.governikus.eumw.eidasmiddleware;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Map.Entry;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import de.governikus.eumw.eidascommon.ErrorCodeException;
import de.governikus.eumw.eidasstarterkit.EidasNaturalPersonAttributes;
import de.governikus.eumw.eidasstarterkit.person_attributes.EidasPersonAttributes;



/**
 * Simple in memory db to store eidas saml request. Stores only a minimum of data
 *
 * @author hohnholt
 */
@Component
public class SessionStore implements AutoCloseable
{

  /**
   * Day in milliseconds.
   */
  static final long DAY_IN_MILLISECONDS = 24 * 60 * 60 * 1000L;

  private static final String DB_DRIVER = "org.h2.Driver";

  @Value("${spring.datasource.url:}")
  private String dbConnectionUrl;

  @Value("${spring.datasource.username:}")
  private String dbUser;

  @Value("${spring.datasource.password:}")
  private String dbPassword;

  private static final String DELETE_QUERY = "DROP TABLE IF EXISTS SESSION;";

  private static final String CREATE_QUERY = "CREATE TABLE SESSION(id IDENTITY PRIMARY KEY, reqid varchar(255),"
                                             + "relaystate varchar(255), destination varchar(255), providername varchar(255), entityid varchar(255), creationtime TIMESTAMP, eidref varchar(255));";

  private static final String CREATE_TABLE_REQUESTED_ATTRIBUTES_QUERY = "CREATE TABLE IF NOT EXISTS REQUESTEDATTRIBUTES(id IDENTITY PRIMARY KEY,reqid varchar(255),"
                                                                        + "name varchar(255), required int, creationtime TIMESTAMP);";

  private static final String INSERT_QUERY = "INSERT INTO SESSION"
                                             + "(reqid, relaystate, destination, providername, entityid, creationtime) values"
                                             + "(?,?,?,?,?,CURRENT_TIMESTAMP());";

  private static final String UPDATE_QUERY = "UPDATE SESSION SET eidref = ? WHERE reqid = ?;";

  private static final String INSERT_REQUESTED_ATTRIBUTES_QUERY = "INSERT INTO REQUESTEDATTRIBUTES"
                                                                  + "(reqid, name, required,creationtime) values"
                                                                  + "(?,?,?,CURRENT_TIMESTAMP());";

  private static final String DELETE_ALL_UNTIL_YESTERDAY = "DELETE FROM SESSION WHERE creationtime < ?;";

  private static final String DELETE_ALL_REQUESTED_ATTRIBUTES_UNTIL_YESTERDAY = "DELETE FROM REQUESTEDATTRIBUTES WHERE creationtime < ?;";

  private static final String SELECTED_BY_EID_REF = "Select * FROM SESSION WHERE eidref = ?;";

  private static final String SELECTED_BY_ID = "Select * FROM SESSION WHERE reqid = ?;";

  private static final String SELECT_REQUESTED_ATTRIBUTES_BY_ID = "Select * FROM REQUESTEDATTRIBUTES WHERE reqid = ?;";

  private Connection dbConnection = null;

  public SessionStore() throws ClassNotFoundException, SQLException
  {
    super();
  }

  void setupDb() throws SQLException
  {
    try (PreparedStatement createPreparedStatement = dbConnection.prepareStatement(DELETE_QUERY))
    {
      createPreparedStatement.execute();
    }
    try (PreparedStatement createPreparedStatement = dbConnection.prepareStatement(CREATE_QUERY))
    {
      createPreparedStatement.execute();
    }
    try (
      PreparedStatement createPreparedStatement = dbConnection.prepareStatement(CREATE_TABLE_REQUESTED_ATTRIBUTES_QUERY))
    {
      createPreparedStatement.execute();
    }
  }

  void cleanUp() throws SQLException
  {
    Timestamp now = new Timestamp(System.currentTimeMillis() - DAY_IN_MILLISECONDS);
    cleanUpByTimeStamp(now);
  }

  void cleanUpByTimeStamp(java.sql.Timestamp now) throws SQLException
  {
    try (PreparedStatement preparedStatement = dbConnection.prepareStatement(DELETE_ALL_UNTIL_YESTERDAY))
    {
      preparedStatement.setTimestamp(1, now);
      preparedStatement.execute();
    }
    try (
      PreparedStatement preparedStatement = dbConnection.prepareStatement(DELETE_ALL_REQUESTED_ATTRIBUTES_UNTIL_YESTERDAY))
    {
      preparedStatement.setTimestamp(1, now);
      preparedStatement.execute();
    }
  }

  public void insert(RequestSession session) throws SQLException
  {
    try (PreparedStatement preparedStatement = dbConnection.prepareStatement(INSERT_QUERY))
    {
      preparedStatement.setString(1, session.getReqId());
      preparedStatement.setString(2, session.getRelayState().orElse(null));
      preparedStatement.setString(3, session.getReqDestination());
      preparedStatement.setString(4, session.getReqProviderName());
      preparedStatement.setString(5, session.getReqProviderEntityId());
      preparedStatement.execute();
    }
    for ( Entry<EidasPersonAttributes, Boolean> entry : session.getRequestedAttributes().entrySet() )
    {
      try (
        PreparedStatement preparedStatement = dbConnection.prepareStatement(INSERT_REQUESTED_ATTRIBUTES_QUERY))
      {
        preparedStatement.setString(1, session.getReqId());
        preparedStatement.setString(2, entry.getKey().getValue());
        preparedStatement.setInt(3, entry.getValue() ? 1 : 0);
        preparedStatement.execute();
      }
    }
  }

  public void update(String reqId, String eidRef) throws SQLException
  {
    try (PreparedStatement preparedStatement = dbConnection.prepareStatement(UPDATE_QUERY))
    {
      preparedStatement.setString(1, eidRef);
      preparedStatement.setString(2, reqId);
      preparedStatement.execute();
    }
  }

  public RequestSession getById(String reqId) throws SQLException, ErrorCodeException
  {
    RequestSession session = null;
    try (PreparedStatement preparedStatement = dbConnection.prepareStatement(SELECTED_BY_ID))
    {
      preparedStatement.setString(1, reqId);
      try (ResultSet rs = preparedStatement.executeQuery())
      {
        if (rs.next())
        {
          session = new RequestSession(rs.getString("relaystate"), rs.getString("reqid"),
                                       rs.getString("destination"), rs.getString("providername"),
                                       rs.getString("entityid"));
        }
      }
    }
    if (session != null)
    {
      try (
        PreparedStatement preparedStatement = dbConnection.prepareStatement(SELECT_REQUESTED_ATTRIBUTES_BY_ID))
      {
        preparedStatement.setString(1, reqId);
        try (ResultSet rs = preparedStatement.executeQuery())
        {
          while (rs.next())
          {
            EidasNaturalPersonAttributes att = EidasNaturalPersonAttributes.getValueOf(rs.getString("name"));
            boolean b = rs.getInt("required") == 1;
            session.getRequestedAttributes().put(att, b);
          }
        }
      }
    }
    return session;
  }

  public RequestSession getByEidRef(String eidRef) throws SQLException, ErrorCodeException
  {
    RequestSession session = null;
    try (PreparedStatement preparedStatement = dbConnection.prepareStatement(SELECTED_BY_EID_REF))
    {
      preparedStatement.setString(1, eidRef);
      try (ResultSet rs = preparedStatement.executeQuery())
      {
        if (rs.next())
        {
          session = new RequestSession(rs.getString("relaystate"), rs.getString("reqid"),
                                       rs.getString("destination"), rs.getString("providername"),
                                       rs.getString("entityid"));
        }
      }
    }
    if (session != null)
    {
      try (
        PreparedStatement preparedStatement = dbConnection.prepareStatement(SELECT_REQUESTED_ATTRIBUTES_BY_ID))
      {
        preparedStatement.setString(1, session.getReqId());
        try (ResultSet rs = preparedStatement.executeQuery())
        {
          while (rs.next())
          {
            EidasNaturalPersonAttributes att = EidasNaturalPersonAttributes.getValueOf(rs.getString("name"));
            boolean b = rs.getInt("required") == 1;
            session.getRequestedAttributes().put(att, b);
          }
        }
      }
    }
    return session;
  }

  @PostConstruct
  void openDBConnection() throws ClassNotFoundException, SQLException
  {
    Class.forName(DB_DRIVER);
    if (dbConnectionUrl == null)
    {
      // memory-based DB as fallback
      dbConnection = DriverManager.getConnection("jdbc:h2:mem:samlreqstore;DB_CLOSE_DELAY=-1", "", "");
    }
    else
    {
      dbConnection = DriverManager.getConnection(dbConnectionUrl, dbUser, dbPassword);
    }
  }

  @Override
  public void close() throws Exception
  {
    if (dbConnection != null)
    {
      dbConnection.close();
    }
  }
}
